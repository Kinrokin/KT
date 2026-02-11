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


FL3_COGNITIVE_FITNESS_POLICY_SCHEMA_ID = "kt.cognitive_fitness_policy.v1"
FL3_COGNITIVE_FITNESS_POLICY_SCHEMA_FILE = "fl3/kt.cognitive_fitness_policy.v1.json"
FL3_COGNITIVE_FITNESS_POLICY_SCHEMA_VERSION_HASH = schema_version_hash(FL3_COGNITIVE_FITNESS_POLICY_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "policy_id",
    "role_weighting",
    "promotion_thresholds",
    "canary_rule",
    "role_drift_rule",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "policy_id"}

_AXES = {
    "reasoning_depth",
    "transfer_capacity",
    "coherence_under_pressure",
    "self_correction",
    "epistemic_behavior",
    "novel_structure",
}


def validate_fl3_cognitive_fitness_policy(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 cognitive fitness policy v1")
    enforce_max_fields(entry, max_fields=48)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_COGNITIVE_FITNESS_POLICY_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_COGNITIVE_FITNESS_POLICY_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")
    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "policy_id")
    validate_created_at_utc_z(entry.get("created_at"))

    role_weighting = require_dict(entry.get("role_weighting"), name="role_weighting")
    enforce_max_fields(role_weighting, max_fields=64)
    if len(role_weighting) < 1:
        raise SchemaValidationError("role_weighting must be non-empty (fail-closed)")
    for role_id, weights in role_weighting.items():
        if not isinstance(role_id, str) or not role_id.strip():
            raise SchemaValidationError("role_weighting keys must be non-empty strings (fail-closed)")
        wmap = require_dict(weights, name=f"role_weighting[{role_id}]")
        enforce_max_fields(wmap, max_fields=16)
        if len(wmap) < 1:
            raise SchemaValidationError("role_weighting per role must be non-empty (fail-closed)")
        total = 0.0
        for axis, w in wmap.items():
            if not isinstance(axis, str) or axis not in _AXES:
                raise SchemaValidationError("role_weighting contains invalid axis (fail-closed)")
            if not isinstance(w, (int, float)) or float(w) < 0.0 or float(w) > 1.0:
                raise SchemaValidationError("role_weighting weights must be in [0,1] (fail-closed)")
            total += float(w)
        if total <= 0.0:
            raise SchemaValidationError("role_weighting total weight must be >0 (fail-closed)")
        if total > 1.0 + 1e-9:
            raise SchemaValidationError("role_weighting total weight must be <=1 (fail-closed)")

    thresholds = require_dict(entry.get("promotion_thresholds"), name="promotion_thresholds")
    enforce_max_fields(thresholds, max_fields=16)
    require_keys(thresholds, required={"promote_min", "shadow_min"})
    reject_unknown_keys(thresholds, allowed={"promote_min", "shadow_min"})
    promote_min = thresholds.get("promote_min")
    shadow_min = thresholds.get("shadow_min")
    if not isinstance(promote_min, (int, float)) or promote_min < 0.0 or promote_min > 1.0:
        raise SchemaValidationError("promotion_thresholds.promote_min must be in [0,1] (fail-closed)")
    if not isinstance(shadow_min, (int, float)) or shadow_min < 0.0 or shadow_min > 1.0:
        raise SchemaValidationError("promotion_thresholds.shadow_min must be in [0,1] (fail-closed)")
    if float(shadow_min) > float(promote_min):
        raise SchemaValidationError("shadow_min must be <= promote_min (fail-closed)")

    if entry.get("canary_rule") != "FAIL_IF_FALSE":
        raise SchemaValidationError("canary_rule invalid (fail-closed)")
    if entry.get("role_drift_rule") != "FAIL_IF_TRUE":
        raise SchemaValidationError("role_drift_rule invalid (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("policy_id") != expected:
        raise SchemaValidationError("policy_id mismatch vs canonical hash surface (fail-closed)")
