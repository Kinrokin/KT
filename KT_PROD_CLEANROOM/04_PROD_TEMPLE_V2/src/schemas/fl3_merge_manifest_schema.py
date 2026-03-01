from __future__ import annotations

from typing import Any, Dict, List, Set

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_hex_64,
    validate_short_string,
)
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_MERGE_MANIFEST_SCHEMA_ID = "kt.merge_manifest.v1"
FL3_MERGE_MANIFEST_SCHEMA_FILE = "fl3/kt.merge_manifest.v1.json"
FL3_MERGE_MANIFEST_SCHEMA_VERSION_HASH = schema_version_hash(FL3_MERGE_MANIFEST_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "merge_manifest_id",
    "base_model_id",
    "role_tag",
    "merge_method",
    "parents",
    "created_at",
)
_OPTIONAL_ORDER = ("notes",)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)
_HASH_DROP_KEYS = {"created_at", "merge_manifest_id"}


def _validate_parents(value: Any) -> List[Dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise SchemaValidationError("parents must be non-empty list (fail-closed)")
    out: List[Dict[str, str]] = []
    for item in value:
        row = require_dict(item, name="parents[]")
        require_keys(row, required={"adapter_root_hash", "adapter_id", "adapter_version"})
        reject_unknown_keys(row, allowed={"adapter_root_hash", "adapter_id", "adapter_version"})
        validate_hex_64(row, "adapter_root_hash")
        adapter_id = str(row.get("adapter_id", "")).strip()
        adapter_version = str(row.get("adapter_version", "")).strip()
        if not adapter_id or not adapter_version:
            raise SchemaValidationError("parents[].adapter_id/adapter_version missing (fail-closed)")
        out.append(
            {
                "adapter_root_hash": str(row["adapter_root_hash"]),
                "adapter_id": adapter_id,
                "adapter_version": adapter_version,
            }
        )
    hashes = [r["adapter_root_hash"] for r in out]
    if hashes != sorted(hashes):
        raise SchemaValidationError("parents must be sorted by adapter_root_hash (fail-closed)")
    if len(set(hashes)) != len(hashes):
        raise SchemaValidationError("parents adapter_root_hash values must be unique (fail-closed)")
    return out


def validate_fl3_merge_manifest(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="merge_manifest")
    enforce_max_fields(entry, max_fields=128)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_MERGE_MANIFEST_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_MERGE_MANIFEST_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "merge_manifest_id")
    validate_created_at_utc_z(entry.get("created_at"))

    validate_short_string(entry, "base_model_id", max_len=128)
    validate_short_string(entry, "role_tag", max_len=128)
    validate_short_string(entry, "merge_method", max_len=128)
    _ = _validate_parents(entry.get("parents"))

    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("merge_manifest_id") != expected:
        raise SchemaValidationError("merge_manifest_id does not match canonical hash surface (fail-closed)")


