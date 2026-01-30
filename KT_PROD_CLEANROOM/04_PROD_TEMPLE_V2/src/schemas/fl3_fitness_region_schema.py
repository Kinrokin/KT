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


FL3_FITNESS_REGION_SCHEMA_ID = "kt.fitness_region.v1"
FL3_FITNESS_REGION_SCHEMA_FILE = "fl3/kt.fitness_region.v1.json"
FL3_FITNESS_REGION_SCHEMA_VERSION_HASH = schema_version_hash(FL3_FITNESS_REGION_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "fitness_id",
    "adapter_version",
    "derived_from",
    "fitness_region",
    "derivation_policy_hash",
    "parent_hash",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "fitness_id"}


def validate_fl3_fitness_region(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 fitness region")
    enforce_max_fields(entry, max_fields=48)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_FITNESS_REGION_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_FITNESS_REGION_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")
    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "fitness_id")
    validate_hex_64(entry, "derivation_policy_hash")
    validate_hex_64(entry, "parent_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    validate_short_string(entry, "adapter_version", max_len=64)
    region = entry.get("fitness_region")
    if region not in {"A", "B", "C"}:
        raise SchemaValidationError("fitness_region must be A, B, or C (fail-closed)")

    derived = require_dict(entry.get("derived_from"), name="derived_from")
    require_keys(derived, required={"signal_quality_hash", "immune_snapshot_hash", "epigenetic_summary_hash"})
    reject_unknown_keys(derived, allowed={"signal_quality_hash", "immune_snapshot_hash", "epigenetic_summary_hash"})
    for k in ("signal_quality_hash", "immune_snapshot_hash", "epigenetic_summary_hash"):
        validate_hex_64(derived, k)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("fitness_id") != expected:
        raise SchemaValidationError("fitness_id does not match canonical hash surface (fail-closed)")

