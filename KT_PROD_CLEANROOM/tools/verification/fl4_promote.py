from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from schemas.schema_files import schema_version_hash
from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import repo_root_from, sha256_json
from tools.verification.fl3_meta_evaluator import verify_job_dir
from tools.verification.fl3_validators import FL3ValidationError, load_fl3_canonical_runtime_paths, validate_schema_bound_object


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"Unable to read JSON (fail-closed): {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"Expected JSON object (fail-closed): {path.as_posix()}")
    validate_schema_bound_object(obj)
    return obj


def _sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _atomic_rename_dir(src: Path, dst: Path) -> None:
    if dst.exists():
        raise FL3ValidationError(f"Promotion target already exists (fail-closed): {dst.as_posix()}")
    os.replace(src, dst)


def _promoted_index_path(*, repo_root: Path) -> Path:
    paths = load_fl3_canonical_runtime_paths(repo_root=repo_root)
    promoted_root = (repo_root / str(paths["exports_adapters_root"])).resolve()
    return promoted_root / "promoted_index.json"


def build_promoted_manifest(
    *,
    adapter_id: str,
    adapter_version: str,
    content_hash: str,
    job_id: str,
    canary_hash_manifest_root_hash: str,
    canary_artifact_hash: str,
    hash_manifest_root_hash: str,
    parent_hash: str,
) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        "schema_id": "kt.promoted_manifest.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.promoted_manifest.v1.json"),
        "promoted_manifest_id": "",
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "content_hash": content_hash,
        "job_id": job_id,
        "canary_hash_manifest_root_hash": canary_hash_manifest_root_hash,
        "canary_artifact_hash": canary_artifact_hash,
        "hash_manifest_root_hash": hash_manifest_root_hash,
        "parent_hash": parent_hash,
        "created_at": utc_now_z(),
    }
    record["promoted_manifest_id"] = sha256_json(
        {k: v for k, v in record.items() if k not in {"created_at", "promoted_manifest_id"}}
    )
    validate_schema_bound_object(record)
    return record


def build_promoted_index(*, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    entries_sorted = sorted(
        entries, key=lambda e: (str(e.get("adapter_id", "")), str(e.get("adapter_version", "")), str(e.get("content_hash", "")))
    )
    record: Dict[str, Any] = {
        "schema_id": "kt.promoted_index.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.promoted_index.v1.json"),
        "index_id": "",
        "entries": entries_sorted,
        "created_at": utc_now_z(),
    }
    record["index_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "index_id"}})
    validate_schema_bound_object(record)
    return record


def _load_or_init_index(*, repo_root: Path) -> Tuple[Path, Dict[str, Any]]:
    idx_path = _promoted_index_path(repo_root=repo_root)
    if idx_path.exists():
        idx = _read_json(idx_path)
        if idx.get("schema_id") != "kt.promoted_index.v1":
            raise FL3ValidationError("promoted_index schema_id mismatch (fail-closed)")
        return idx_path, idx
    # Initialize empty index deterministically.
    idx = build_promoted_index(entries=[])
    return idx_path, idx


def promote_job_dir(
    *,
    repo_root: Path,
    job_dir: Path,
    canary_artifact_path: Path,
    out_report: Optional[Path],
) -> int:
    job_dir = job_dir.resolve()
    if not job_dir.exists():
        raise FL3ValidationError(f"job_dir missing (fail-closed): {job_dir.as_posix()}")

    job = _read_json(job_dir / "job.json")
    # Lab → canonical segregation: promotion must fail-closed unless the source is MRT-0 canonical.
    # Canonical is defined operationally here as training_mode=head_only (AdapterType.A-only).
    if job.get("training_mode") != "head_only":
        raise FL3ValidationError("Non-canonical training_mode cannot promote into canonical index (fail-closed)")

    # Pre-verify the job directory under canonical meta-evaluator rules.
    verify_job_dir(repo_root=repo_root, job_dir=job_dir)

    promotion = _read_json(job_dir / "promotion.json")
    if promotion.get("schema_id") != "kt.factory.promotion.v1":
        raise FL3ValidationError("promotion schema_id mismatch (fail-closed)")
    if promotion.get("decision") != "PROMOTE":
        raise FL3ValidationError("promotion decision is not PROMOTE (fail-closed)")

    canary = _read_json(canary_artifact_path)
    if canary.get("schema_id") != "kt.canary_artifact.v1":
        raise FL3ValidationError("canary_artifact schema_id mismatch (fail-closed)")
    if canary.get("canary_result") != "PASS":
        raise FL3ValidationError("canary_result != PASS (fail-closed)")
    canary_hash = sha256_json(canary)

    # Content address of the promoted package is the job_dir hash_manifest.root_hash.
    hm = _read_json(job_dir / "hash_manifest.json")
    if hm.get("schema_id") != "kt.hash_manifest.v1":
        raise FL3ValidationError("hash_manifest schema_id mismatch (fail-closed)")
    content_hash = str(hm.get("root_hash", ""))
    if not content_hash or len(content_hash) != 64:
        raise FL3ValidationError("hash_manifest.root_hash missing (fail-closed)")

    adapter_id = str(job.get("adapter_id"))
    adapter_version = str(job.get("adapter_version"))

    # Promotion target layout: exports/adapters/<adapter_id>/<adapter_version>/<content_hash>/
    paths = load_fl3_canonical_runtime_paths(repo_root=repo_root)
    promoted_root = (repo_root / str(paths["exports_adapters_root"])).resolve()
    final_dir = (promoted_root / adapter_id / adapter_version / content_hash).resolve()

    # Copy job_dir to a temp sibling directory under promoted_root, then atomic rename.
    final_dir.parent.mkdir(parents=True, exist_ok=True)
    tmp_parent = Path(tempfile.mkdtemp(prefix="promote_tmp_", dir=str(final_dir.parent)))
    tmp_dir = tmp_parent / content_hash
    shutil.copytree(job_dir, tmp_dir)

    # Write promoted_manifest into the promoted package.
    promoted_manifest = build_promoted_manifest(
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        content_hash=content_hash,
        job_id=str(job.get("job_id")),
        canary_hash_manifest_root_hash=str(canary.get("hash_manifest_root_hash")),
        canary_artifact_hash=canary_hash,
        hash_manifest_root_hash=content_hash,
        parent_hash=str(promotion.get("promotion_id", "0" * 64)),
    )
    (tmp_dir / "promoted_manifest.json").write_text(
        json.dumps(promoted_manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8"
    )

    # Re-verify the promoted copy (job_dir verifier ignores extra files not listed in job_dir_manifest).
    verify_job_dir(repo_root=repo_root, job_dir=tmp_dir)
    validate_schema_bound_object(_read_json(tmp_dir / "promoted_manifest.json"))

    # Atomic directory rename into final location.
    _atomic_rename_dir(tmp_dir, final_dir)
    shutil.rmtree(tmp_parent, ignore_errors=True)

    # Update promoted_index atomically.
    idx_path, idx_obj = _load_or_init_index(repo_root=repo_root)
    entries = idx_obj.get("entries") if isinstance(idx_obj.get("entries"), list) else []
    cleaned: List[Dict[str, Any]] = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        cleaned.append(
            {
                "adapter_id": str(e.get("adapter_id", "")),
                "adapter_version": str(e.get("adapter_version", "")),
                "content_hash": str(e.get("content_hash", "")),
                "promoted_manifest_ref": str(e.get("promoted_manifest_ref", "")),
            }
        )
    cleaned.append(
        {
            "adapter_id": adapter_id,
            "adapter_version": adapter_version,
            "content_hash": content_hash,
            "promoted_manifest_ref": str((final_dir / "promoted_manifest.json").relative_to(repo_root).as_posix()),
        }
    )
    idx_new = build_promoted_index(entries=cleaned)
    _atomic_write_text(idx_path, json.dumps(idx_new, indent=2, sort_keys=True, ensure_ascii=True) + "\n")

    report = {
        "schema_id": "kt.fl4.promotion_report.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.fl4.promotion_report.v1.json"),
        "job_dir": str(job_dir.relative_to(repo_root).as_posix()),
        "promoted_dir": str(final_dir.relative_to(repo_root).as_posix()),
        "promoted_index_path": str(idx_path.relative_to(repo_root).as_posix()),
        "content_hash": content_hash,
        "promoted_manifest_id": str(promoted_manifest.get("promoted_manifest_id")),
        "promoted_manifest_sha256": _sha256_file(final_dir / "promoted_manifest.json"),
        "canary_artifact_hash": canary_hash,
    }
    validate_schema_bound_object(report)
    if out_report:
        out_report.parent.mkdir(parents=True, exist_ok=True)
        out_report.write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
    else:
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True))

    return 0


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="FL4 atomic promotion tool (MRT-0 AdapterType.A-only).")
    ap.add_argument("--job-dir", required=True, help="Path to a factory job_dir (must have promotion decision PROMOTE).")
    ap.add_argument("--canary-artifact", required=True, help="Path to kt.canary_artifact.v1 JSON (must be PASS).")
    ap.add_argument("--out", default="", help="Optional output JSON report path.")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_root = repo_root_from(Path(__file__))
    out = Path(args.out) if args.out else None
    return int(
        promote_job_dir(
            repo_root=repo_root,
            job_dir=Path(args.job_dir),
            canary_artifact_path=Path(args.canary_artifact),
            out_report=out,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
