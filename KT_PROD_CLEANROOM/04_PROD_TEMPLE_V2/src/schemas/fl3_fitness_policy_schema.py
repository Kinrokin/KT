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


FL3_FITNESS_POLICY_SCHEMA_ID = "kt.fl3_fitness_policy.v1"
FL3_FITNESS_POLICY_SCHEMA_FILE = "fl3/kt.fl3_fitness_policy.v1.json"
FL3_FITNESS_POLICY_SCHEMA_VERSION_HASH = schema_version_hash(FL3_FITNESS_POLICY_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "policy_id",
    "risk_max",
    "governance_strikes_max",
    "min_immune_events",
    "ece_max",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "policy_id"}


def validate_fl3_fitness_policy(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 fitness policy")
    enforce_max_fields(entry, max_fields=32)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_FITNESS_POLICY_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_FITNESS_POLICY_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")
    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "policy_id")
    validate_created_at_utc_z(entry.get("created_at"))

    risk_max = entry.get("risk_max")
    if not isinstance(risk_max, (int, float)) or risk_max < 0.0 or risk_max > 1.0:
        raise SchemaValidationError("risk_max must be in [0,1] (fail-closed)")
    ece_max = entry.get("ece_max")
    if not isinstance(ece_max, (int, float)) or ece_max < 0.0 or ece_max > 1.0:
        raise SchemaValidationError("ece_max must be in [0,1] (fail-closed)")
    for f in ("governance_strikes_max", "min_immune_events"):
        v = entry.get(f)
        if not isinstance(v, int) or v < 0:
            raise SchemaValidationError(f"{f} must be >=0 int (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("policy_id") != expected:
        raise SchemaValidationError("policy_id does not match canonical hash surface (fail-closed)")

