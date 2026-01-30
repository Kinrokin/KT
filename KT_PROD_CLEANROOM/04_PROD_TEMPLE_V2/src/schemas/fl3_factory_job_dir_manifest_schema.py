from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_FACTORY_JOB_DIR_MANIFEST_SCHEMA_ID = "kt.factory.job_dir_manifest.v1"
FL3_FACTORY_JOB_DIR_MANIFEST_SCHEMA_FILE = "fl3/kt.factory.job_dir_manifest.v1.json"
FL3_FACTORY_JOB_DIR_MANIFEST_SCHEMA_VERSION_HASH = schema_version_hash(FL3_FACTORY_JOB_DIR_MANIFEST_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "job_dir_manifest_id",
    "job_id",
    "files",
    "hash_manifest_root_hash",
    "parent_hash",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "job_dir_manifest_id"}


def validate_fl3_factory_job_dir_manifest(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL4 job_dir_manifest")
    enforce_max_fields(entry, max_fields=128)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_FACTORY_JOB_DIR_MANIFEST_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_FACTORY_JOB_DIR_MANIFEST_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "job_dir_manifest_id")
    validate_hex_64(entry, "job_id")
    validate_hex_64(entry, "hash_manifest_root_hash")
    validate_hex_64(entry, "parent_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    files = entry.get("files")
    if not isinstance(files, list) or len(files) < 1:
        raise SchemaValidationError("files must be non-empty list (fail-closed)")

    prev_path = None
    for item in files:
        f = require_dict(item, name="job_dir_manifest file entry")
        if set(f.keys()) != {"path", "required", "sha256"}:
            raise SchemaValidationError("job_dir_manifest file entry keys mismatch (fail-closed)")
        path = f.get("path")
        if not isinstance(path, str) or not path.strip():
            raise SchemaValidationError("job_dir_manifest file path must be non-empty (fail-closed)")
        if path.startswith("/") or ".." in path.split("/"):
            raise SchemaValidationError("job_dir_manifest file path must be clean relative path (fail-closed)")
        if prev_path is not None and path < prev_path:
            raise SchemaValidationError("job_dir_manifest files must be sorted by path (fail-closed)")
        prev_path = path
        if not isinstance(f.get("required"), bool):
            raise SchemaValidationError("job_dir_manifest required must be boolean (fail-closed)")
        validate_hex_64(f, "sha256")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("job_dir_manifest_id") != expected:
        raise SchemaValidationError("job_dir_manifest_id does not match canonical hash surface (fail-closed)")

