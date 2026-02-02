from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_canonical_json_bytes, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64, validate_short_string
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_PROMOTED_INDEX_SCHEMA_ID = "kt.promoted_index.v1"
FL3_PROMOTED_INDEX_SCHEMA_FILE = "fl3/kt.promoted_index.v1.json"
FL3_PROMOTED_INDEX_SCHEMA_VERSION_HASH = schema_version_hash(FL3_PROMOTED_INDEX_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "index_id",
    "entries",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "index_id"}


def validate_fl3_promoted_index(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="promoted_index")
    enforce_max_fields(entry, max_fields=128)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    enforce_max_canonical_json_bytes(entry, max_bytes=512 * 1024)

    if entry.get("schema_id") != FL3_PROMOTED_INDEX_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_PROMOTED_INDEX_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")
    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "index_id")
    validate_created_at_utc_z(entry.get("created_at"))

    entries = entry.get("entries")
    if not isinstance(entries, list):
        raise SchemaValidationError("entries must be list (fail-closed)")
    for item in entries:
        e = require_dict(item, name="promoted_index entry")
        if set(e.keys()) != {"adapter_id", "adapter_version", "content_hash", "promoted_manifest_ref"}:
            raise SchemaValidationError("promoted_index entry keys mismatch (fail-closed)")
        validate_short_string(e, "adapter_id", max_len=128)
        validate_short_string(e, "adapter_version", max_len=64)
        validate_hex_64(e, "content_hash")
        validate_short_string(e, "promoted_manifest_ref", max_len=256)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("index_id") != expected:
        raise SchemaValidationError("index_id does not match canonical hash surface (fail-closed)")

