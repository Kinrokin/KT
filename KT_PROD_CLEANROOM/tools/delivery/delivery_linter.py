from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.training.fl3_factory.manifests import sha256_file
from tools.verification.fl3_canonical import repo_root_from
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object


def _read_json_dict(path: Path, *, name: str) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"Unreadable JSON {name} (fail-closed): {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"{name} must be a JSON object (fail-closed): {path.as_posix()}")
    return obj


def lint_delivery_dir(*, delivery_dir: Path) -> Dict[str, Any]:
    _ = repo_root_from(Path(__file__))  # fail-fast if repo root isn't detectable
    delivery_dir = delivery_dir.resolve()

    manifest_path = delivery_dir / "delivery_pack_manifest.json"
    manifest = _read_json_dict(manifest_path, name="delivery_pack_manifest.json")
    validate_schema_bound_object(manifest)
    if manifest.get("schema_id") != "kt.delivery_pack_manifest.v1":
        raise FL3ValidationError("delivery_pack_manifest schema_id mismatch (fail-closed)")

    # Delivery pack must contain a PASS secret scan summary.
    summary_path = delivery_dir / "secret_scan_summary.json"
    summary = _read_json_dict(summary_path, name="secret_scan_summary.json")
    validate_schema_bound_object(summary)
    if str(summary.get("status")) != "PASS":
        raise FL3ValidationError(f"delivery pack secret scan status={summary.get('status')} (fail-closed)")

    # No unresolved placeholders in client-facing docs.
    for rel in ("reports", "dashboard"):
        root = delivery_dir / rel
        if not root.exists():
            continue
        for p in sorted(root.rglob("*")):
            if not p.is_file():
                continue
            if p.suffix.lower() not in {".md", ".html"}:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
            if "{{" in text or "}}" in text:
                raise FL3ValidationError(f"Unresolved template placeholders detected (fail-closed): {p.as_posix()}")

    # Verify every manifest file entry against the filesystem.
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise FL3ValidationError("delivery_pack_manifest.files must be non-empty list (fail-closed)")
    for item in files:
        if not isinstance(item, dict):
            raise FL3ValidationError("delivery_pack_manifest.files[] must be objects (fail-closed)")
        rel = str(item.get("path", "")).strip()
        expected_sha = str(item.get("sha256", "")).strip()
        expected_bytes = item.get("bytes")
        if not rel or not expected_sha:
            raise FL3ValidationError("delivery_pack_manifest.files entries require path and sha256 (fail-closed)")
        p = (delivery_dir / rel).resolve()
        try:
            p.relative_to(delivery_dir)
        except Exception as exc:  # noqa: BLE001
            raise FL3ValidationError(f"delivery manifest path escapes delivery_dir (fail-closed): {rel}") from exc
        if not p.exists() or not p.is_file():
            raise FL3ValidationError(f"delivery manifest file missing on disk (fail-closed): {rel}")
        actual_sha = sha256_file(p)
        if actual_sha != expected_sha:
            raise FL3ValidationError(f"delivery manifest sha mismatch (fail-closed): {rel}")
        if not isinstance(expected_bytes, int) or expected_bytes < 0:
            raise FL3ValidationError(f"delivery manifest bytes invalid (fail-closed): {rel}")
        if int(p.stat().st_size) != int(expected_bytes):
            raise FL3ValidationError(f"delivery manifest bytes mismatch (fail-closed): {rel}")

    return {"status": "PASS", "inputs": {"delivery_dir": delivery_dir.as_posix()}, "checks": {"manifest_verified": True}}


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Fail-closed linter for KT delivery packs.")
    ap.add_argument("--delivery-dir", required=True)
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    report = lint_delivery_dir(delivery_dir=Path(args.delivery_dir))
    print(json.dumps(report, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FL3ValidationError as exc:
        raise SystemExit(f"FAIL_CLOSED: {exc}") from exc
