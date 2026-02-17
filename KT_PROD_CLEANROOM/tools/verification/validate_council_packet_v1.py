from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.verification.fl3_canonical import canonical_json, repo_root_from
from tools.verification.fl3_validators import FL3ValidationError
from tools.verification.worm_write import write_text_worm


_MANIFEST_SCHEMA_ID = "kt.council_packet_manifest_local.v1"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_json_dict(path: Path, *, name: str) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"FAIL_CLOSED: unreadable JSON {name}: {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"FAIL_CLOSED: {name} must be a JSON object: {path.as_posix()}")
    return obj


def _compute_manifest_id(manifest: Dict[str, Any]) -> str:
    payload = {k: v for k, v in manifest.items() if k not in {"created_at", "manifest_id"}}
    return _sha256_bytes(canonical_json(payload).encode("utf-8"))


def _normalize_path_string(p: str) -> str:
    return str(p).replace("\\", "/").strip()


def validate_council_packet(
    *,
    repo_root: Path,
    manifest_path: Path,
    packet_dir: Path,
    forbid_extras: bool = True,
) -> Dict[str, Any]:
    manifest_path = manifest_path.resolve()
    packet_dir = packet_dir.resolve()
    if not manifest_path.exists():
        raise FL3ValidationError(f"FAIL_CLOSED: council manifest missing: {manifest_path.as_posix()}")
    if not packet_dir.exists() or not packet_dir.is_dir():
        raise FL3ValidationError(f"FAIL_CLOSED: council packet dir missing: {packet_dir.as_posix()}")

    manifest = _read_json_dict(manifest_path, name="council_manifest")
    if str(manifest.get("schema_id", "")).strip() != _MANIFEST_SCHEMA_ID:
        raise FL3ValidationError("FAIL_CLOSED: council manifest schema_id mismatch")
    got_id = str(manifest.get("manifest_id", "")).strip()
    if len(got_id) != 64:
        raise FL3ValidationError("FAIL_CLOSED: council manifest_id missing/invalid")
    expected_id = _compute_manifest_id(manifest)
    if got_id != expected_id:
        raise FL3ValidationError("FAIL_CLOSED: council manifest_id mismatch")

    dest_dir_decl = _normalize_path_string(str(manifest.get("dest_dir", "")))
    if not dest_dir_decl:
        raise FL3ValidationError("FAIL_CLOSED: council manifest dest_dir missing")

    files_val = manifest.get("files")
    if not isinstance(files_val, list) or not files_val:
        raise FL3ValidationError("FAIL_CLOSED: council manifest files[] missing/invalid")

    expected_relpaths: List[str] = []
    missing: List[str] = []
    mismatches: List[Dict[str, Any]] = []

    for row_any in files_val:
        if not isinstance(row_any, dict):
            raise FL3ValidationError("FAIL_CLOSED: council manifest files[] must be objects")
        relpath = _normalize_path_string(str(row_any.get("path", "")))
        sha = str(row_any.get("sha256", "")).strip().lower()
        size = row_any.get("size_bytes")
        if not relpath or not relpath.startswith(dest_dir_decl.rstrip("/") + "/"):
            raise FL3ValidationError("FAIL_CLOSED: council manifest file path escapes dest_dir")
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise FL3ValidationError("FAIL_CLOSED: council manifest file sha256 missing/invalid")
        if not isinstance(size, int) or size < 0:
            raise FL3ValidationError("FAIL_CLOSED: council manifest file size_bytes missing/invalid")

        expected_relpaths.append(relpath)
        abs_path = (repo_root / Path(relpath)).resolve()
        if not abs_path.exists() or not abs_path.is_file():
            missing.append(relpath)
            continue
        data = abs_path.read_bytes()
        got_sha = _sha256_bytes(data)
        got_size = len(data)
        if got_sha != sha or got_size != int(size):
            mismatches.append(
                {
                    "path": relpath,
                    "expected_sha256": sha,
                    "got_sha256": got_sha,
                    "expected_size_bytes": int(size),
                    "got_size_bytes": got_size,
                }
            )

    expected_set = set(expected_relpaths)
    actual_set = set(
        _normalize_path_string(str(Path(dest_dir_decl) / p.name))
        for p in sorted(packet_dir.glob("*"), key=lambda x: x.name)
        if p.is_file()
    )
    extras = sorted(actual_set - expected_set)
    if forbid_extras and extras:
        # Extras introduce ambiguity about what "the packet" is.
        raise FL3ValidationError("FAIL_CLOSED: council packet dir contains unexpected extra files")

    ok = not missing and not mismatches and (not extras or not forbid_extras)
    return {
        "status": "PASS" if ok else "FAIL",
        "manifest_path": manifest_path.as_posix(),
        "manifest_id": got_id,
        "packet_dir": packet_dir.as_posix(),
        "counts": {
            "expected_files": len(expected_relpaths),
            "missing": len(missing),
            "mismatched": len(mismatches),
            "extras": len(extras),
        },
        "missing": missing,
        "mismatches": mismatches,
        "extras": extras,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Fail-closed validation of KT Council Packet v1 (manifest + file hashes).")
    ap.add_argument(
        "--manifest",
        default="KT_PROD_CLEANROOM/AUDITS/COUNCIL_PACKET/kt_council_packet_v1.manifest.json",
        help="Path to council packet manifest (repo-relative by default).",
    )
    ap.add_argument(
        "--packet-dir",
        default="KT_PROD_CLEANROOM/AUDITS/COUNCIL_PACKET/V1",
        help="Directory containing the canonicalized council packet files.",
    )
    ap.add_argument("--out-dir", required=True, help="Write council_packet_validation_report.json under this directory (WORM).")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_root = repo_root_from(Path(__file__))

    manifest_path = Path(str(args.manifest))
    if not manifest_path.is_absolute():
        manifest_path = (repo_root / manifest_path).resolve()

    packet_dir = Path(str(args.packet_dir))
    if not packet_dir.is_absolute():
        packet_dir = (repo_root / packet_dir).resolve()

    out_dir = Path(str(args.out_dir))
    if not out_dir.is_absolute():
        out_dir = (repo_root / out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    report = validate_council_packet(repo_root=repo_root, manifest_path=manifest_path, packet_dir=packet_dir, forbid_extras=True)
    out_path = out_dir / "council_packet_validation_report.json"
    write_text_worm(
        path=out_path,
        text=json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        label="council_packet_validation_report.json",
    )
    if report.get("status") != "PASS":
        raise SystemExit("FAIL_CLOSED: council packet validation failed")
    print(out_path.as_posix())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FL3ValidationError as exc:
        raise SystemExit(f"FAIL_CLOSED: {exc}") from exc

