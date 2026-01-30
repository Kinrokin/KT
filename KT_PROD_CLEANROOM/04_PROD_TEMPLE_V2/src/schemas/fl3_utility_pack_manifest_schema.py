from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64, validate_short_string
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_UTILITY_PACK_MANIFEST_SCHEMA_ID = "kt.utility_pack_manifest.v1"
FL3_UTILITY_PACK_MANIFEST_SCHEMA_FILE = "fl3/kt.utility_pack_manifest.v1.json"
FL3_UTILITY_PACK_MANIFEST_SCHEMA_VERSION_HASH = schema_version_hash(FL3_UTILITY_PACK_MANIFEST_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "manifest_id",
    "utility_pack_id",
    "files",
    "utility_pack_hash",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "manifest_id"}


def validate_fl3_utility_pack_manifest(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="utility_pack_manifest")
    enforce_max_fields(entry, max_fields=64)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_UTILITY_PACK_MANIFEST_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_UTILITY_PACK_MANIFEST_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "manifest_id")
    validate_hex_64(entry, "utility_pack_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    validate_short_string(entry, "utility_pack_id", max_len=128)
    files = entry.get("files")
    if not isinstance(files, list) or len(files) < 1:
        raise SchemaValidationError("files must be non-empty list (fail-closed)")
    prev = None
    for item in files:
        f = require_dict(item, name="utility_pack file")
        if set(f.keys()) != {"path", "sha256"}:
            raise SchemaValidationError("utility_pack file keys mismatch (fail-closed)")
        path = f.get("path")
        if not isinstance(path, str) or not path.strip():
            raise SchemaValidationError("utility_pack file path must be string (fail-closed)")
        if prev is not None and path < prev:
            raise SchemaValidationError("utility_pack files must be sorted by path (fail-closed)")
        prev = path
        validate_hex_64(f, "sha256")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("manifest_id") != expected:
        raise SchemaValidationError("manifest_id does not match canonical hash surface (fail-closed)")

