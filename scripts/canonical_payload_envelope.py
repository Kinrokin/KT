#!/usr/bin/env python3
"""Create or verify KT deterministic payload + nondeterministic derivation envelope."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import socket
import sys
import stat
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def repo_root_default() -> Path:
    return Path(__file__).resolve().parents[1]


def resolve_repo_payload_path(repo_root: Path, payload_path: str) -> tuple[Path, str]:
    if not payload_path or not payload_path.strip():
        raise SystemExit("payload_path_empty")
    if "\\" in payload_path:
        raise SystemExit("payload_path_backslash")
    win = PureWindowsPath(payload_path)
    if win.is_absolute() or win.drive or win.root:
        raise SystemExit("payload_path_windows_anchor")
    rel = Path(payload_path)
    if rel.is_absolute():
        raise SystemExit("payload_path_absolute")
    if any(part in {"", ".", ".."} for part in rel.parts):
        raise SystemExit("payload_path_traversal")

    root = repo_root.resolve(strict=True)
    current = root
    for part in rel.parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError as exc:
            raise SystemExit("payload_path_missing") from exc
        if stat.S_ISLNK(info.st_mode):
            raise SystemExit("payload_path_symlink")
    resolved = current.resolve(strict=True)
    try:
        repo_rel = resolved.relative_to(root)
    except ValueError as exc:
        raise SystemExit("payload_path_escape") from exc
    if not stat.S_ISREG(resolved.stat().st_mode):
        raise SystemExit("payload_path_nonregular")
    return resolved, repo_rel.as_posix()


def resolve_repo_metadata_path(repo_root: Path, metadata_path: str) -> Path:
    """Resolve envelope metadata paths relative to repo root in verify mode."""
    if not metadata_path or not metadata_path.strip():
        raise SystemExit("metadata_path_empty")
    raw = Path(metadata_path)
    root = repo_root.resolve(strict=True)
    if raw.is_absolute():
        candidate = raw
    else:
        win = PureWindowsPath(metadata_path)
        if win.is_absolute() or win.drive or win.root:
            raise SystemExit("metadata_path_windows_anchor")
        if "\\" in metadata_path:
            raise SystemExit("metadata_path_backslash")
        if any(part in {"", ".", ".."} for part in raw.parts):
            raise SystemExit("metadata_path_traversal")
        candidate = root / raw
    try:
        rel = candidate.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        raise SystemExit("metadata_path_escape") from exc
    current = root
    for part in rel.parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError as exc:
            raise SystemExit("metadata_path_missing") from exc
        if stat.S_ISLNK(info.st_mode):
            raise SystemExit("metadata_path_symlink")
    resolved = current.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise SystemExit("metadata_path_escape") from exc
    if not stat.S_ISREG(resolved.stat().st_mode):
        raise SystemExit("metadata_path_nonregular")
    return resolved


def clean_verify_value(value: Any, field_name: str, origin: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise SystemExit(f"{origin}_{field_name}_invalid_type")
    if not value.strip():
        raise SystemExit(f"{origin}_{field_name}_empty")
    return value


def payload_value(payload: dict[str, Any], field_name: str, keys: tuple[str, ...]) -> str | None:
    for key in keys:
        if key in payload:
            value = clean_verify_value(payload[key], field_name, "payload")
            if value is not None:
                return value
    return None


def envelope_value(envelope: dict[str, Any], field_name: str, key: str) -> str | None:
    return clean_verify_value(envelope.get(key), field_name, "envelope")


def verification_expectation(
    *,
    explicit: str | None,
    payload: dict[str, Any],
    payload_keys: tuple[str, ...],
    envelope: dict[str, Any],
    envelope_key: str,
    field_name: str,
) -> str:
    """Resolve verify metadata with explicit args, then payload, then envelope fallback."""
    payload_field = payload_value(payload, field_name, payload_keys)
    if explicit is not None:
        explicit_value = clean_verify_value(explicit, field_name, "explicit")
        if payload_field is not None and explicit_value != payload_field:
            raise SystemExit(f"explicit_{field_name}_payload_mismatch")
        return explicit_value
    if payload_field is not None:
        return payload_field
    fallback = envelope_value(envelope, field_name, envelope_key)
    if fallback is not None:
        return fallback
    raise SystemExit(f"missing_{field_name}")


def build_envelope(payload: Any, *, payload_schema_id: str, payload_path: str, generated_from_head: str, source_set_sha256: str, build_execution_id: str) -> dict[str, Any]:
    payload_sha = sha256_bytes(canonical_bytes(payload))
    generator_sha = sha256_bytes(Path(__file__).read_bytes())
    host_fingerprint = sha256_bytes(f"{socket.gethostname()}|{platform.python_version()}|{platform.system()}|{platform.machine()}".encode("utf-8"))
    body = {
        "schema_id": "kt.derivation_envelope.v1",
        "payload_schema_id": payload_schema_id,
        "payload_path": payload_path,
        "payload_sha256": payload_sha,
        "generator_sha256": generator_sha,
        "source_set_sha256": source_set_sha256,
        "generated_from_head": generated_from_head,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "build_execution_id": build_execution_id,
        "build_host_fingerprint_sha256": host_fingerprint,
    }
    return {**body, "envelope_sha256": sha256_bytes(canonical_bytes(body))}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--payload")
    p.add_argument("--envelope")
    p.add_argument("--payload-schema-id")
    p.add_argument("--head")
    p.add_argument("--source-set-sha256")
    p.add_argument("--build-execution-id", default=os.environ.get("GITHUB_RUN_ID", "local"))
    p.add_argument("--repo-root", default=str(repo_root_default()))
    p.add_argument("--verify", action="store_true")
    args = p.parse_args()
    repo_root = Path(args.repo_root)
    if args.verify:
        provided_payload = args.payload is not None
        provided_envelope = args.envelope is not None
        if provided_payload != provided_envelope:
            p.error("--verify requires --payload and --envelope to be supplied together, or neither for repo defaults")
        if not provided_payload:
            args.payload = "reports/livewire_pr_a_system_evidence_graph_payload.json"
            args.envelope = "reports/livewire_pr_a_system_evidence_graph_payload.envelope.json"
    else:
        for name in ("payload", "envelope", "payload_schema_id", "head", "source_set_sha256"):
            if getattr(args, name) is None:
                p.error(f"--{name.replace('_', '-')} is required unless --verify defaults are used")
    payload_path, normalized_payload_path = resolve_repo_payload_path(repo_root, args.payload)
    envelope_path = resolve_repo_metadata_path(repo_root, args.envelope) if args.verify else Path(args.envelope)
    payload = read(payload_path)
    if args.verify:
        envelope = read(envelope_path)
        expected_payload_schema_id = verification_expectation(
            explicit=args.payload_schema_id,
            payload=payload,
            payload_keys=("schema_id",),
            envelope=envelope,
            envelope_key="payload_schema_id",
            field_name="payload_schema_id",
        )
        expected_head = verification_expectation(
            explicit=args.head,
            payload=payload,
            payload_keys=("generated_from_head", "compiled_from_head"),
            envelope=envelope,
            envelope_key="generated_from_head",
            field_name="head",
        )
        expected_source_set_sha256 = verification_expectation(
            explicit=args.source_set_sha256,
            payload=payload,
            payload_keys=("source_set_sha256",),
            envelope=envelope,
            envelope_key="source_set_sha256",
            field_name="source_set_sha256",
        )
        expected_payload_sha = sha256_bytes(canonical_bytes(payload))
        if envelope["payload_sha256"] != expected_payload_sha:
            raise SystemExit("payload_digest_mismatch")
        body = {k: v for k, v in envelope.items() if k != "envelope_sha256"}
        if envelope["envelope_sha256"] != sha256_bytes(canonical_bytes(body)):
            raise SystemExit("envelope_digest_mismatch")
        if envelope["payload_schema_id"] != expected_payload_schema_id:
            raise SystemExit("envelope_payload_schema_mismatch")
        if envelope["generated_from_head"] != expected_head:
            raise SystemExit("envelope_head_mismatch")
        if envelope["source_set_sha256"] != expected_source_set_sha256:
            raise SystemExit("envelope_source_set_mismatch")
        if envelope["payload_path"] != normalized_payload_path:
            raise SystemExit("envelope_payload_path_mismatch")
        print("canonical_payload_envelope_verify_pass")
        return 0
    envelope = build_envelope(payload, payload_schema_id=args.payload_schema_id, payload_path=normalized_payload_path, generated_from_head=args.head, source_set_sha256=args.source_set_sha256, build_execution_id=args.build_execution_id)
    write(envelope_path, envelope)
    print(json.dumps({"payload_sha256": envelope["payload_sha256"], "envelope_sha256": envelope["envelope_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
