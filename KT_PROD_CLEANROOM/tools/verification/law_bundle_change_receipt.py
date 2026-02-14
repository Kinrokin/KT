from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from schemas.schema_files import schema_version_hash
from tools.verification.fl3_canonical import repo_root_from
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_file_for_bundle(*, relpath: str, data: bytes) -> str:
    # Must match tools.verification.fl3_meta_evaluator._hash_file_for_bundle
    if relpath.lower().endswith(".json"):
        obj = json.loads(data.decode("utf-8"))
        # EPIC_15 determinism: keep bundle hashing free of canary fixed-point drift.
        # Must match tools.verification.fl3_meta_evaluator._hash_file_for_bundle.
        rel_norm = relpath.replace("\\", "/")
        if rel_norm.endswith("FL4_DETERMINISM_CONTRACT.json") and isinstance(obj, dict):
            obj = dict(obj)
            obj.pop("canary_expected_hash_manifest_root_hash", None)
            obj.pop("determinism_contract_id", None)
        canon = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return _sha256_bytes(canon)

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return _sha256_bytes(data)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return _sha256_bytes(text.encode("utf-8"))


def _compute_bundle_hash_from_maps(*, file_digests: Dict[str, str], laws_obj: Any) -> str:
    paths = sorted(file_digests.keys())
    lines = [f"{rel}:{file_digests[rel]}\n" for rel in paths]
    laws_canon = json.dumps(laws_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    lines.append(f"__LAWS__:{_sha256_bytes(laws_canon)}\n")
    return _sha256_bytes("".join(lines).encode("utf-8"))


def _git_show_bytes(*, repo_root: Path, ref: str, relpath: str) -> bytes:
    rel_norm = relpath.replace("\\", "/")
    try:
        p = subprocess.run(
            ["git", "show", f"{ref}:{rel_norm}"],
            cwd=str(repo_root),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as exc:
        raise FL3ValidationError(
            f"git show failed (fail-closed): ref={ref} relpath={relpath} stderr={exc.stderr.decode('utf-8', errors='replace')[-400:]}"
        ) from exc
    return p.stdout


def _read_json_dict_from_bytes(data: bytes, *, name: str) -> Dict[str, Any]:
    try:
        obj = json.loads(data.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"Unreadable JSON {name} (fail-closed)") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"{name} must be object (fail-closed)")
    return obj


def _read_law_bundle_from_ref(*, repo_root: Path, ref: str, relpath: str) -> Dict[str, Any]:
    data = _git_show_bytes(repo_root=repo_root, ref=ref, relpath=relpath)
    return _read_json_dict_from_bytes(data, name=f"{relpath}@{ref}")


def _read_law_bundle_from_worktree(*, repo_root: Path, relpath: str) -> Dict[str, Any]:
    p = (repo_root / relpath).resolve()
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"Unable to read law bundle JSON (fail-closed): {relpath}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"Law bundle must be object (fail-closed): {relpath}")
    return obj


def _file_digest_map_for_bundle_ref(*, repo_root: Path, ref: str, files: List[Dict[str, Any]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in files:
        if not isinstance(item, dict):
            raise FL3ValidationError("LAW_BUNDLE files must contain objects (fail-closed)")
        rel = str(item.get("path", "")).strip()
        if not rel:
            raise FL3ValidationError("LAW_BUNDLE file entry missing path (fail-closed)")
        data = _git_show_bytes(repo_root=repo_root, ref=ref, relpath=rel)
        out[rel] = _hash_file_for_bundle(relpath=rel, data=data)
    return out


def _file_digest_map_for_bundle_worktree(*, repo_root: Path, files: List[Dict[str, Any]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in files:
        if not isinstance(item, dict):
            raise FL3ValidationError("LAW_BUNDLE files must contain objects (fail-closed)")
        rel = str(item.get("path", "")).strip()
        if not rel:
            raise FL3ValidationError("LAW_BUNDLE file entry missing path (fail-closed)")
        p = (repo_root / rel).resolve()
        if not p.exists() or not p.is_file():
            raise FL3ValidationError(f"LAW_BUNDLE file missing on disk (fail-closed): {rel}")
        out[rel] = _hash_file_for_bundle(relpath=rel, data=p.read_bytes())
    return out


def _sorted_added_removed(rows: List[Tuple[str, str]]) -> List[Dict[str, str]]:
    return [{"path": p, "sha256": sha} for p, sha in sorted(rows, key=lambda x: x[0])]


def _sorted_modified(rows: List[Tuple[str, str, str]]) -> List[Dict[str, str]]:
    return [{"path": p, "old_sha256": o, "new_sha256": n} for p, o, n in sorted(rows, key=lambda x: x[0])]


def build_law_bundle_change_receipt(
    *,
    bundle_id: str,
    old_ref: str,
    old_bundle_hash: str,
    new_bundle_hash: str,
    added: List[Tuple[str, str]],
    removed: List[Tuple[str, str]],
    modified: List[Tuple[str, str, str]],
    created_at: str,
) -> Dict[str, Any]:
    obj: Dict[str, Any] = {
        "schema_id": "kt.law_bundle_change_receipt.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.law_bundle_change_receipt.v1.json"),
        "receipt_id": "",
        "bundle_id": bundle_id,
        "old_ref": old_ref,
        "old_bundle_hash": old_bundle_hash,
        "new_bundle_hash": new_bundle_hash,
        "diff": {
            "added": _sorted_added_removed(added),
            "removed": _sorted_added_removed(removed),
            "modified": _sorted_modified(modified),
        },
        "counts": {"added": len(added), "removed": len(removed), "modified": len(modified)},
        "created_at": created_at,
    }
    # receipt_id drop keys must match schema validator.
    payload = {k: v for k, v in obj.items() if k not in {"created_at", "receipt_id"}}
    obj["receipt_id"] = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
    validate_schema_bound_object(obj)
    return obj


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Create a schema-bound law bundle diff receipt (append-only).")
    ap.add_argument("--bundle-relpath", default="KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.json")
    ap.add_argument("--old-ref", default="HEAD")
    ap.add_argument("--out", default=None, help="Output path. Default: KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_CHANGE_RECEIPT_FL3_<ts>.json")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_root = repo_root_from(Path(__file__))
    bundle_rel = str(args.bundle_relpath).replace("\\", "/")

    old_bundle = _read_law_bundle_from_ref(repo_root=repo_root, ref=str(args.old_ref), relpath=bundle_rel)
    new_bundle = _read_law_bundle_from_worktree(repo_root=repo_root, relpath=bundle_rel)
    if str(old_bundle.get("bundle_id")) != str(new_bundle.get("bundle_id")):
        raise FL3ValidationError("bundle_id mismatch between old and new law bundles (fail-closed)")
    bundle_id = str(new_bundle.get("bundle_id", "")).strip()
    if not bundle_id:
        raise FL3ValidationError("bundle_id missing (fail-closed)")

    old_files = old_bundle.get("files")
    new_files = new_bundle.get("files")
    if not isinstance(old_files, list) or not isinstance(new_files, list):
        raise FL3ValidationError("LAW_BUNDLE files must be lists (fail-closed)")

    old_map = _file_digest_map_for_bundle_ref(repo_root=repo_root, ref=str(args.old_ref), files=old_files)
    new_map = _file_digest_map_for_bundle_worktree(repo_root=repo_root, files=new_files)

    old_hash = _compute_bundle_hash_from_maps(file_digests=old_map, laws_obj=old_bundle.get("laws", []))
    new_hash = _compute_bundle_hash_from_maps(file_digests=new_map, laws_obj=new_bundle.get("laws", []))

    old_paths = set(old_map.keys())
    new_paths = set(new_map.keys())
    added = [(p, new_map[p]) for p in sorted(new_paths - old_paths)]
    removed = [(p, old_map[p]) for p in sorted(old_paths - new_paths)]
    modified = [(p, old_map[p], new_map[p]) for p in sorted(old_paths & new_paths) if old_map[p] != new_map[p]]

    created_at = _utc_now_z()
    receipt = build_law_bundle_change_receipt(
        bundle_id=bundle_id,
        old_ref=str(args.old_ref),
        old_bundle_hash=old_hash,
        new_bundle_hash=new_hash,
        added=added,
        removed=removed,
        modified=modified,
        created_at=created_at,
    )

    if args.out:
        out_path = Path(args.out).resolve()
    else:
        audits_dir = repo_root / "KT_PROD_CLEANROOM" / "AUDITS"
        out_path = audits_dir / f"LAW_BUNDLE_CHANGE_RECEIPT_FL3_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with out_path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
    except FileExistsError as exc:
        raise FL3ValidationError("Refusing to overwrite existing change receipt (fail-closed)") from exc

    print(out_path.as_posix())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FL3ValidationError as exc:
        raise SystemExit(f"FAIL_CLOSED: {exc}") from exc
