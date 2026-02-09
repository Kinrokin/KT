from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.verification.strict_json import load_no_dupes


class Phase2PromoteMRT1Error(RuntimeError):
    pass


def _repo_root_from(this_file: Path) -> Path:
    p = this_file.resolve()
    for parent in [p] + list(p.parents):
        if (parent / "KT_PROD_CLEANROOM").exists():
            return parent
    raise Phase2PromoteMRT1Error("FAIL_CLOSED: unable to locate repo root (missing KT_PROD_CLEANROOM/)")


def _bootstrap_syspath(*, repo_root: Path) -> None:
    """
    Must be runnable via `python -m tools.verification.phase2_promote_mrt1` without relying on PYTHONPATH.
    """
    import sys

    src_root = (repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src").resolve()
    cleanroom_root = (repo_root / "KT_PROD_CLEANROOM").resolve()
    for p in (str(src_root), str(cleanroom_root)):
        if p not in sys.path:
            sys.path.insert(0, p)


def _canonical_json(obj: object) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_canonical_json(obj), encoding="utf-8", newline="\n")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _enforce_offline_and_guard() -> None:
    if os.environ.get("KT_LIVE") != "0":
        raise Phase2PromoteMRT1Error("FAIL_CLOSED: promotion requires offline mode: KT_LIVE must be 0")
    if os.environ.get("KT_IO_GUARD") != "1":
        raise Phase2PromoteMRT1Error("FAIL_CLOSED: promotion requires IO guard: KT_IO_GUARD must be 1")
    if os.environ.get("KT_IO_GUARD_DENY_NETWORK", "1") != "1":
        raise Phase2PromoteMRT1Error("FAIL_CLOSED: promotion requires deny-network: KT_IO_GUARD_DENY_NETWORK must be 1")
    if not os.environ.get("KT_IO_GUARD_ALLOWED_WRITE_ROOTS", "").strip():
        raise Phase2PromoteMRT1Error("FAIL_CLOSED: KT_IO_GUARD_ALLOWED_WRITE_ROOTS (JSON list) must be set")


def _require_io_guard_installed() -> None:
    # Ensure sitecustomize runs (installs kt_io_guard) once sys.path includes KT_PROD_CLEANROOM.
    import importlib

    importlib.import_module("sitecustomize")
    try:
        import kt_io_guard  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise Phase2PromoteMRT1Error(f"FAIL_CLOSED: IO guard not importable as kt_io_guard: {exc.__class__.__name__}")
    guard = getattr(kt_io_guard, "_GLOBAL_GUARD", None)
    if guard is None:
        raise Phase2PromoteMRT1Error("FAIL_CLOSED: IO guard not installed (_GLOBAL_GUARD is None)")


def _validate_clean_relpath(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise Phase2PromoteMRT1Error(f"FAIL_CLOSED: {field} must be a non-empty string")
    norm = value.replace("\\", "/").strip()
    p = Path(norm)
    if p.is_absolute():
        raise Phase2PromoteMRT1Error(f"FAIL_CLOSED: {field} must be a relative path")
    if any(part in {".", ".."} for part in p.parts):
        raise Phase2PromoteMRT1Error(f"FAIL_CLOSED: {field} must not contain '.' or '..' segments")
    return norm


def _is_symlink(path: Path) -> bool:
    try:
        return path.is_symlink()
    except Exception:
        return False


def _atomic_rename_dir(src: Path, dst: Path) -> None:
    if dst.exists():
        raise Phase2PromoteMRT1Error(f"FAIL_CLOSED: promotion target already exists: {dst.as_posix()}")
    os.replace(src, dst)


def _verify_manifest_files(*, run_dir: Path, manifest: Dict[str, Any]) -> None:
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise Phase2PromoteMRT1Error("FAIL_CLOSED: adapter_weight_manifest.files missing/invalid")

    allowed_ext = {".safetensors", ".json", ".txt"}
    max_file_bytes = 2 * 1024 * 1024 * 1024  # 2 GiB (fail-closed)
    max_total_bytes = 4 * 1024 * 1024 * 1024  # 4 GiB (fail-closed)
    total_bytes = 0
    seen: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict):
            raise Phase2PromoteMRT1Error("FAIL_CLOSED: manifest file entry must be object")
        rel = entry.get("path")
        sha = entry.get("sha256")
        b = entry.get("bytes")
        if not isinstance(rel, str) or not rel.strip():
            raise Phase2PromoteMRT1Error("FAIL_CLOSED: manifest file path missing/invalid")
        rel_norm = rel.replace("\\", "/").strip()
        p = Path(rel_norm)
        if p.is_absolute() or ".." in p.parts or "." in p.parts:
            raise Phase2PromoteMRT1Error("FAIL_CLOSED: manifest file path must be clean relative")
        if rel_norm in seen:
            raise Phase2PromoteMRT1Error("FAIL_CLOSED: duplicate file path in manifest")
        seen.add(rel_norm)
        if not isinstance(sha, str) or len(sha) != 64:
            raise Phase2PromoteMRT1Error("FAIL_CLOSED: manifest file sha256 missing/invalid")
        if not isinstance(b, int) or b < 0:
            raise Phase2PromoteMRT1Error("FAIL_CLOSED: manifest file bytes missing/invalid")
        if int(b) > max_file_bytes:
            raise Phase2PromoteMRT1Error("FAIL_CLOSED: manifest file exceeds size ceiling")

        abs_p = (run_dir / p).resolve()
        try:
            abs_p.relative_to(run_dir.resolve())
        except Exception:
            raise Phase2PromoteMRT1Error("FAIL_CLOSED: manifest file escapes run_dir")
        if not abs_p.exists() or not abs_p.is_file():
            raise Phase2PromoteMRT1Error(f"FAIL_CLOSED: manifest file missing on disk: {rel_norm}")
        if _is_symlink(abs_p):
            raise Phase2PromoteMRT1Error("FAIL_CLOSED: symlink forbidden in MRT-1 artifacts")
        if abs_p.suffix not in allowed_ext:
            raise Phase2PromoteMRT1Error(f"FAIL_CLOSED: forbidden file extension in MRT-1 artifacts: {abs_p.suffix}")
        if int(abs_p.stat().st_size) != int(b):
            raise Phase2PromoteMRT1Error("FAIL_CLOSED: manifest bytes mismatch")
        if _sha256_file(abs_p) != sha:
            raise Phase2PromoteMRT1Error("FAIL_CLOSED: manifest sha256 mismatch")
        total_bytes += int(b)
        if total_bytes > max_total_bytes:
            raise Phase2PromoteMRT1Error("FAIL_CLOSED: total artifact bytes exceed ceiling")

    # Strict, but with explicit, deterministic sidecars:
    # - train_request.json (contains created_at; excluded from content_hash surface)
    # - train_receipt.json (contains created_at + content_hash; excluded from content_hash surface)
    # - adapter_weight_manifest.json (self-reference)
    allowed_sidecars = {"train_request.json", "train_receipt.json", "adapter_weight_manifest.json"}
    actual = sorted([p.relative_to(run_dir).as_posix() for p in run_dir.rglob("*") if p.is_file()])
    actual_set = set(actual)
    allowed_set = set(seen) | allowed_sidecars
    if actual_set != allowed_set:
        raise Phase2PromoteMRT1Error("FAIL_CLOSED: on-disk file set mismatch vs (manifest.files + allowed sidecars)")
    if not allowed_sidecars.issubset(actual_set):
        raise Phase2PromoteMRT1Error("FAIL_CLOSED: missing required sidecar file(s) for MRT-1 package")

    # Sidecars must be root-level, non-symlink, and extension-allowlisted.
    for rel in allowed_sidecars:
        p = (run_dir / rel).resolve()
        if not p.exists() or not p.is_file():
            raise Phase2PromoteMRT1Error("FAIL_CLOSED: required sidecar missing on disk")
        if _is_symlink(p):
            raise Phase2PromoteMRT1Error("FAIL_CLOSED: symlink forbidden in MRT-1 artifacts")
        if p.suffix not in allowed_ext:
            raise Phase2PromoteMRT1Error("FAIL_CLOSED: forbidden sidecar extension in MRT-1 artifacts")
        if int(p.stat().st_size) > max_file_bytes:
            raise Phase2PromoteMRT1Error("FAIL_CLOSED: sidecar exceeds size ceiling")
        total_bytes += int(p.stat().st_size)
        if total_bytes > max_total_bytes:
            raise Phase2PromoteMRT1Error("FAIL_CLOSED: total artifact bytes exceed ceiling")


def _build_promotion_receipt(
    *,
    pinned_sha: str,
    adapter_id: str,
    adapter_version: str,
    train_request_id: str,
    train_receipt_ref_rel: str,
    train_receipt_sha256: str,
    artifact_manifest_ref_rel: str,
    artifact_manifest_sha256: str,
    shadow_dir_rel: str,
    promoted_dir_rel: str,
    content_hash: str,
    status: str,
    failure_reason: Optional[str],
) -> Dict[str, Any]:
    from schemas.fl3_schema_common import sha256_hex_of_obj  # type: ignore
    from schemas.schema_files import schema_version_hash  # type: ignore
    from tools.verification.fl3_validators import validate_schema_bound_object  # type: ignore

    receipt: Dict[str, Any] = {
        "schema_id": "kt.phase2_promotion_receipt.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.phase2_promotion_receipt.v1.json"),
        "schema_version": 1,
        "promotion_receipt_id": "",
        "train_request_id": train_request_id,
        "pinned_sha": pinned_sha,
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "training_mode": "lora_mrt1",
        "status": status,
        "failure_reason": failure_reason,
        "train_receipt_ref": {"path": train_receipt_ref_rel, "sha256": train_receipt_sha256},
        "artifact_manifest_ref": {"path": artifact_manifest_ref_rel, "sha256": artifact_manifest_sha256},
        "output_package": {
            "shadow_dir": shadow_dir_rel,
            "promoted_dir": promoted_dir_rel,
            "content_hash": content_hash,
        },
        "io_guard_receipt_glob": "io_guard_receipt*.json",
        "created_at": _utc_now_z(),
    }
    receipt["promotion_receipt_id"] = sha256_hex_of_obj(
        receipt, drop_keys={"promotion_receipt_id", "created_at"}
    )
    validate_schema_bound_object(receipt)
    return receipt


def promote(*, repo_root: Path, train_receipt_path: Path, out_path: Optional[Path]) -> int:
    _enforce_offline_and_guard()
    _require_io_guard_installed()

    from tools.verification.fl3_validators import assert_path_under_exports_mrt1, validate_schema_bound_object  # type: ignore

    train_receipt_path = train_receipt_path.resolve()
    if not train_receipt_path.exists():
        raise Phase2PromoteMRT1Error(f"FAIL_CLOSED: train_receipt not found: {train_receipt_path.as_posix()}")

    train_receipt = load_no_dupes(train_receipt_path)
    if not isinstance(train_receipt, dict):
        raise Phase2PromoteMRT1Error("FAIL_CLOSED: train_receipt must be JSON object")
    validate_schema_bound_object(train_receipt)
    if train_receipt.get("schema_id") != "kt.phase2_train_receipt.v1":
        raise Phase2PromoteMRT1Error("FAIL_CLOSED: train_receipt schema_id mismatch")
    if train_receipt.get("training_mode") != "lora_mrt1":
        raise Phase2PromoteMRT1Error("FAIL_CLOSED: train_receipt training_mode mismatch")
    if train_receipt.get("status") != "PASS":
        raise Phase2PromoteMRT1Error("FAIL_CLOSED: cannot promote FAILED training receipt")

    adapter_id = str(train_receipt.get("adapter_id", "")).strip()
    adapter_version = str(train_receipt.get("adapter_version", "")).strip()
    train_receipt_id = str(train_receipt.get("train_receipt_id", "")).strip()
    train_request_id = str(train_receipt.get("train_request_id", "")).strip()
    content_hash = str((train_receipt.get("output_package") or {}).get("content_hash", "")).strip()
    if not adapter_id or not adapter_version or len(train_receipt_id) != 64 or len(train_request_id) != 64 or len(content_hash) != 64:
        raise Phase2PromoteMRT1Error(
            "FAIL_CLOSED: train_receipt surface malformed (adapter_id/version/receipt_id/request_id/content_hash)"
        )

    run_dir = train_receipt_path.parent.resolve()
    assert_path_under_exports_mrt1(repo_root=repo_root, path=run_dir, allow_promoted=False)

    req_path = run_dir / "train_request.json"
    req = load_no_dupes(req_path)
    if not isinstance(req, dict):
        raise Phase2PromoteMRT1Error("FAIL_CLOSED: train_request.json must be JSON object")
    validate_schema_bound_object(req)
    if req.get("schema_id") != "kt.phase2_train_request.v1":
        raise Phase2PromoteMRT1Error("FAIL_CLOSED: train_request schema_id mismatch")
    if str(req.get("train_request_id", "")).strip() != train_request_id:
        raise Phase2PromoteMRT1Error("FAIL_CLOSED: train_request_id mismatch between request and receipt")

    export_promoted_root = str(((req.get("output") or {}).get("export_root_promoted")) or "").strip()
    promoted_root_rel = _validate_clean_relpath(export_promoted_root, field="train_request.output.export_root_promoted")
    if not promoted_root_rel.startswith("KT_PROD_CLEANROOM/exports/adapters_mrt1"):
        raise Phase2PromoteMRT1Error("FAIL_CLOSED: export_root_promoted must be under KT_PROD_CLEANROOM/exports/adapters_mrt1")

    final_dir_rel = f"{promoted_root_rel}/{adapter_id}/{adapter_version}/{content_hash}".replace("\\", "/")
    final_dir = (repo_root / final_dir_rel).resolve()
    assert_path_under_exports_mrt1(repo_root=repo_root, path=final_dir, allow_promoted=True)

    manifest_path = run_dir / "adapter_weight_manifest.json"
    manifest = load_no_dupes(manifest_path)
    if not isinstance(manifest, dict):
        raise Phase2PromoteMRT1Error("FAIL_CLOSED: adapter_weight_manifest.json must be JSON object")
    validate_schema_bound_object(manifest)
    if manifest.get("schema_id") != "kt.adapter_weight_artifact_manifest.v1":
        raise Phase2PromoteMRT1Error("FAIL_CLOSED: weight manifest schema_id mismatch")
    manifest_id = str(manifest.get("manifest_id", "")).strip()
    if len(manifest_id) != 64:
        raise Phase2PromoteMRT1Error("FAIL_CLOSED: weight manifest manifest_id missing/invalid")
    if str(manifest.get("root_hash", "")).strip() != content_hash:
        raise Phase2PromoteMRT1Error("FAIL_CLOSED: content_hash mismatch between receipt and manifest.root_hash")

    _verify_manifest_files(run_dir=run_dir, manifest=manifest)

    # Copy into a temp sibling directory under final_dir.parent, then atomic rename into final_dir.
    final_dir.parent.mkdir(parents=True, exist_ok=True)
    tmp_parent = Path(tempfile.mkdtemp(prefix="promote_mrt1_tmp_", dir=str(final_dir.parent)))
    tmp_dir = tmp_parent / content_hash
    shutil.copytree(run_dir, tmp_dir)

    # Verify copied tree matches manifest too.
    _verify_manifest_files(run_dir=tmp_dir, manifest=manifest)

    _atomic_rename_dir(tmp_dir, final_dir)
    shutil.rmtree(tmp_parent, ignore_errors=True)

    train_receipt_ref_rel = str(train_receipt_path.relative_to(repo_root).as_posix())
    manifest_ref_rel = str(manifest_path.relative_to(repo_root).as_posix())

    receipt = _build_promotion_receipt(
        pinned_sha=str(train_receipt.get("pinned_sha", "")),
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        train_request_id=train_request_id,
        train_receipt_ref_rel=train_receipt_ref_rel,
        train_receipt_sha256=train_receipt_id,
        artifact_manifest_ref_rel=manifest_ref_rel,
        artifact_manifest_sha256=manifest_id,
        shadow_dir_rel=str((train_receipt.get("output_package") or {}).get("shadow_dir", "")),
        promoted_dir_rel=final_dir_rel,
        content_hash=content_hash,
        status="PASS",
        failure_reason=None,
    )

    if out_path:
        out_path = out_path.resolve()
        _write_json(out_path, receipt)
    else:
        print(_canonical_json(receipt))
    return 0


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Phase2 MRT-1 promotion tool (atomic; fail-closed).")
    ap.add_argument("--train-receipt", required=True, help="Path to a kt.phase2_train_receipt.v1.json (must be PASS).")
    ap.add_argument("--out", default="", help="Optional output JSON path for kt.phase2_promotion_receipt.v1.")
    return ap.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_root = _repo_root_from(Path(__file__))
    _bootstrap_syspath(repo_root=repo_root)
    out = Path(args.out) if str(args.out).strip() else None
    return int(promote(repo_root=repo_root, train_receipt_path=Path(args.train_receipt), out_path=out))


if __name__ == "__main__":
    raise SystemExit(main())
