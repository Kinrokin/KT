from __future__ import annotations

from typing import Any, Dict, Set

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


FL3_SHADOW_ADAPTER_MANIFEST_SCHEMA_ID = "kt.shadow_adapter_manifest.v1"
FL3_SHADOW_ADAPTER_MANIFEST_SCHEMA_FILE = "fl3/kt.shadow_adapter_manifest.v1.json"
FL3_SHADOW_ADAPTER_MANIFEST_SCHEMA_VERSION_HASH = schema_version_hash(FL3_SHADOW_ADAPTER_MANIFEST_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "shadow_id",
    "adapter_version",
    "storage_format",
    "checksum",
    "fitness_region",
    "signed_by",
    "parent_hash",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "shadow_id"}


def validate_fl3_shadow_adapter_manifest(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 shadow adapter manifest")
    enforce_max_fields(entry, max_fields=32)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_SHADOW_ADAPTER_MANIFEST_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_SHADOW_ADAPTER_MANIFEST_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")
    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "shadow_id")
    validate_hex_64(entry, "checksum")
    validate_hex_64(entry, "parent_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    validate_short_string(entry, "adapter_version", max_len=64)
    validate_short_string(entry, "signed_by", max_len=128)
    if entry.get("fitness_region") != "B":
        raise SchemaValidationError("shadow fitness_region must be B (fail-closed)")
    if entry.get("storage_format") not in {"safetensors", "jsonl", "npz"}:
        raise SchemaValidationError("storage_format must be safetensors/jsonl/npz (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("shadow_id") != expected:
        raise SchemaValidationError("shadow_id does not match canonical hash surface (fail-closed)")

