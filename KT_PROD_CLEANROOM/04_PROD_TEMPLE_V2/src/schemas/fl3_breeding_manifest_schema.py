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
from schemas.fl3_schema_common import ensure_sorted_str_list, sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_BREEDING_MANIFEST_SCHEMA_ID = "kt.breeding_manifest.v1"
FL3_BREEDING_MANIFEST_SCHEMA_FILE = "fl3/kt.breeding_manifest.v1.json"
FL3_BREEDING_MANIFEST_SCHEMA_VERSION_HASH = schema_version_hash(FL3_BREEDING_MANIFEST_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "breeding_id",
    "child_adapter_version",
    "parent_adapters",
    "shadow_injection",
    "parent_hash",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "breeding_id"}


def validate_fl3_breeding_manifest(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 breeding manifest")
    enforce_max_fields(entry, max_fields=64)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_BREEDING_MANIFEST_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_BREEDING_MANIFEST_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")
    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "breeding_id")
    validate_hex_64(entry, "parent_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    validate_short_string(entry, "child_adapter_version", max_len=64)
    parents = ensure_sorted_str_list(entry.get("parent_adapters"), field="parent_adapters")
    if len(parents) < 1:
        raise SchemaValidationError("parent_adapters must be non-empty (fail-closed)")

    inj = require_dict(entry.get("shadow_injection"), name="shadow_injection")
    require_keys(inj, required={"batch_fraction", "shadow_sources"})
    reject_unknown_keys(inj, allowed={"batch_fraction", "shadow_sources"})
    frac = inj.get("batch_fraction")
    if not isinstance(frac, (int, float)) or frac < 0.0 or frac > 1.0:
        raise SchemaValidationError("shadow_injection.batch_fraction must be in [0,1] (fail-closed)")
    sources = ensure_sorted_str_list(inj.get("shadow_sources"), field="shadow_sources")
    if len(sources) < 1:
        raise SchemaValidationError("shadow_injection.shadow_sources must be non-empty (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("breeding_id") != expected:
        raise SchemaValidationError("breeding_id does not match canonical hash surface (fail-closed)")

