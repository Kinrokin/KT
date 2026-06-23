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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


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
    p.add_argument("--payload", required=True)
    p.add_argument("--envelope", required=True)
    p.add_argument("--payload-schema-id", required=True)
    p.add_argument("--head", required=True)
    p.add_argument("--source-set-sha256", required=True)
    p.add_argument("--build-execution-id", default=os.environ.get("GITHUB_RUN_ID", "local"))
    p.add_argument("--verify", action="store_true")
    args = p.parse_args()
    payload_path = Path(args.payload)
    envelope_path = Path(args.envelope)
    payload = read(payload_path)
    if args.verify:
        envelope = read(envelope_path)
        expected_payload_sha = sha256_bytes(canonical_bytes(payload))
        if envelope["payload_sha256"] != expected_payload_sha:
            raise SystemExit("payload_digest_mismatch")
        body = {k: v for k, v in envelope.items() if k != "envelope_sha256"}
        if envelope["envelope_sha256"] != sha256_bytes(canonical_bytes(body)):
            raise SystemExit("envelope_digest_mismatch")
        if envelope["generated_from_head"] != args.head:
            raise SystemExit("envelope_head_mismatch")
        if envelope["source_set_sha256"] != args.source_set_sha256:
            raise SystemExit("envelope_source_set_mismatch")
        print("canonical_payload_envelope_verify_pass")
        return 0
    envelope = build_envelope(payload, payload_schema_id=args.payload_schema_id, payload_path=str(payload_path), generated_from_head=args.head, source_set_sha256=args.source_set_sha256, build_execution_id=args.build_execution_id)
    write(envelope_path, envelope)
    print(json.dumps({"payload_sha256": envelope["payload_sha256"], "envelope_sha256": envelope["envelope_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
