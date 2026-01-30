from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import sha256_json
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object


def _schema_hash(schema_file: str) -> str:
    from schemas.schema_files import schema_version_hash  # type: ignore

    return schema_version_hash(schema_file)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_hash_manifest_root_hash(entries: List[Dict[str, str]]) -> str:
    """
    Root hash = sha256(canonical_json({"entries": sorted(entries)})).
    Canonical JSON uses sorted keys + stable separators (via sha256_json).
    """
    entries_sorted = sorted(entries, key=lambda e: str(e.get("path", "")))
    return sha256_json({"entries": entries_sorted})


def build_hash_manifest(*, entries: List[Dict[str, str]], parent_hash: str) -> Dict[str, Any]:
    entries_sorted = sorted(entries, key=lambda e: str(e.get("path", "")))
    root_hash = compute_hash_manifest_root_hash(entries_sorted)
    record: Dict[str, Any] = {
        "schema_id": "kt.hash_manifest.v1",
        "schema_version_hash": _schema_hash("fl3/kt.hash_manifest.v1.json"),
        "manifest_id": "",
        "entries": entries_sorted,
        "root_hash": root_hash,
        "parent_hash": parent_hash,
        "created_at": utc_now_z(),
    }
    record["manifest_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "manifest_id"}})
    validate_schema_bound_object(record)
    return record


def build_job_dir_manifest(
    *,
    job_id: str,
    files: List[Dict[str, Any]],
    hash_manifest_root_hash: str,
    parent_hash: str,
) -> Dict[str, Any]:
    files_sorted = sorted(files, key=lambda f: str(f.get("path", "")))
    record: Dict[str, Any] = {
        "schema_id": "kt.factory.job_dir_manifest.v1",
        "schema_version_hash": _schema_hash("fl3/kt.factory.job_dir_manifest.v1.json"),
        "job_dir_manifest_id": "",
        "job_id": job_id,
        "files": files_sorted,
        "hash_manifest_root_hash": hash_manifest_root_hash,
        "parent_hash": parent_hash,
        "created_at": utc_now_z(),
    }
    record["job_dir_manifest_id"] = sha256_json(
        {k: v for k, v in record.items() if k not in {"created_at", "job_dir_manifest_id"}}
    )
    validate_schema_bound_object(record)
    return record


def build_phase_trace(*, job_id: str, phases: List[Dict[str, Any]], no_stub_executed: bool, parent_hash: str) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        "schema_id": "kt.factory.phase_trace.v1",
        "schema_version_hash": _schema_hash("fl3/kt.factory.phase_trace.v1.json"),
        "phase_trace_id": "",
        "job_id": job_id,
        "phases": phases,
        "no_stub_executed": bool(no_stub_executed),
        "parent_hash": parent_hash,
        "created_at": utc_now_z(),
    }
    record["phase_trace_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "phase_trace_id"}})
    validate_schema_bound_object(record)
    return record


@dataclass(frozen=True)
class ManifestOutputs:
    hash_manifest: Dict[str, Any]
    job_dir_manifest: Dict[str, Any]


def list_job_dir_files_for_manifest(*, job_dir: Path) -> List[Path]:
    """
    Enumerate all files under job_dir for hash manifest.
    Deterministic ordering is enforced by sorting on POSIX paths.
    """
    paths: List[Path] = []
    for p in job_dir.rglob("*"):
        if p.is_file():
            paths.append(p)
    paths.sort(key=lambda p: p.relative_to(job_dir).as_posix())
    return paths


def build_manifests_for_job_dir(
    *,
    job_dir: Path,
    job_id: str,
    parent_hash: str,
    required_relpaths: Iterable[str],
) -> ManifestOutputs:
    required_set = set(required_relpaths)

    all_files = list_job_dir_files_for_manifest(job_dir=job_dir)
    entries: List[Dict[str, str]] = []
    files: List[Dict[str, Any]] = []
    for p in all_files:
        rel = p.relative_to(job_dir).as_posix()
        digest = sha256_file(p)
        entries.append({"path": rel, "sha256": digest})
        files.append({"path": rel, "required": rel in required_set, "sha256": digest})

    # Fail-closed: required files must exist in job_dir.
    present = {e["path"] for e in entries}
    missing = sorted(required_set - present)
    if missing:
        raise FL3ValidationError(f"Missing required job_dir files (fail-closed): {missing}")

    hash_manifest = build_hash_manifest(entries=entries, parent_hash=parent_hash)
    job_dir_manifest = build_job_dir_manifest(
        job_id=job_id,
        files=files,
        hash_manifest_root_hash=str(hash_manifest["root_hash"]),
        parent_hash=str(hash_manifest["manifest_id"]),
    )
    return ManifestOutputs(hash_manifest=hash_manifest, job_dir_manifest=job_dir_manifest)


def write_manifests_for_job_dir(
    *,
    job_dir: Path,
    job_id: str,
    parent_hash: str,
    required_relpaths: Iterable[str],
) -> ManifestOutputs:
    """
    Write FL4 job_dir hash artifacts in a non-circular way.

    - hash_manifest.json hashes *content* files (excludes hash_manifest.json and job_dir_manifest.json).
    - job_dir_manifest.json lists all files except itself, and includes the hash_manifest.json sha256.
    - Neither manifest includes its own sha256, avoiding recursion.
    """
    required_set = set(required_relpaths)

    # 1) Hash-manifest entries: everything except the manifests themselves.
    excluded_for_hash_entries = {"hash_manifest.json", "job_dir_manifest.json"}
    all_files = list_job_dir_files_for_manifest(job_dir=job_dir)
    entries: List[Dict[str, str]] = []
    for p in all_files:
        rel = p.relative_to(job_dir).as_posix()
        if rel in excluded_for_hash_entries:
            continue
        entries.append({"path": rel, "sha256": sha256_file(p)})

    # Fail-closed: required files must exist among the job_dir filesystem (excluding the manifests, which we will write).
    present = {p.relative_to(job_dir).as_posix() for p in all_files}
    missing = sorted(required_set - present)
    if missing:
        raise FL3ValidationError(f"Missing required job_dir files (fail-closed): {missing}")

    hash_manifest = build_hash_manifest(entries=entries, parent_hash=parent_hash)
    # Write hash_manifest first so job_dir_manifest can include its sha256.
    from tools.training.fl3_factory.io import write_schema_object

    _ = write_schema_object(path=job_dir / "hash_manifest.json", obj=hash_manifest)

    # 2) Job-dir manifest: list all files except itself (includes hash_manifest.json).
    excluded_for_job_manifest = {"job_dir_manifest.json"}
    all_files_after = list_job_dir_files_for_manifest(job_dir=job_dir)
    files: List[Dict[str, Any]] = []
    for p in all_files_after:
        rel = p.relative_to(job_dir).as_posix()
        if rel in excluded_for_job_manifest:
            continue
        digest = sha256_file(p)
        files.append({"path": rel, "required": rel in required_set or rel == "hash_manifest.json", "sha256": digest})

    job_dir_manifest = build_job_dir_manifest(
        job_id=job_id,
        files=files,
        hash_manifest_root_hash=str(hash_manifest["root_hash"]),
        parent_hash=str(hash_manifest["manifest_id"]),
    )
    _ = write_schema_object(path=job_dir / "job_dir_manifest.json", obj=job_dir_manifest)

    return ManifestOutputs(hash_manifest=hash_manifest, job_dir_manifest=job_dir_manifest)
