from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_hex_64,
)
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_HASH_MANIFEST_SCHEMA_ID = "kt.hash_manifest.v1"
FL3_HASH_MANIFEST_SCHEMA_FILE = "fl3/kt.hash_manifest.v1.json"
FL3_HASH_MANIFEST_SCHEMA_VERSION_HASH = schema_version_hash(FL3_HASH_MANIFEST_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "manifest_id",
    "entries",
    "root_hash",
    "parent_hash",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "manifest_id"}


def validate_fl3_hash_manifest(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 hash manifest")
    enforce_max_fields(entry, max_fields=64)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_HASH_MANIFEST_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_HASH_MANIFEST_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "manifest_id")
    validate_hex_64(entry, "root_hash")
    validate_hex_64(entry, "parent_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    entries = entry.get("entries")
    if not isinstance(entries, list) or len(entries) < 1:
        raise SchemaValidationError("entries must be non-empty list (fail-closed)")

    prev_path = None
    for item in entries:
        e = require_dict(item, name="hash_manifest entry")
        if set(e.keys()) != {"path", "sha256"}:
            raise SchemaValidationError("hash_manifest entry keys must be path,sha256 (fail-closed)")
        path = e.get("path")
        if not isinstance(path, str) or not path.strip():
            raise SchemaValidationError("hash_manifest entry.path must be non-empty string (fail-closed)")
        if path.startswith("/") or ".." in path.split("/"):
            raise SchemaValidationError("hash_manifest entry.path must be clean relative path (fail-closed)")
        if prev_path is not None and path < prev_path:
            raise SchemaValidationError("hash_manifest entries must be sorted by path (fail-closed)")
        prev_path = path
        validate_hex_64(e, "sha256")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("manifest_id") != expected:
        raise SchemaValidationError("manifest_id does not match canonical hash surface (fail-closed)")

