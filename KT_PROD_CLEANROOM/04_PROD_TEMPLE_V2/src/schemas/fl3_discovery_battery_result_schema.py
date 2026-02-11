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


FL3_DISCOVERY_BATTERY_RESULT_SCHEMA_ID = "kt.discovery_battery_result.v1"
FL3_DISCOVERY_BATTERY_RESULT_SCHEMA_FILE = "fl3/kt.discovery_battery_result.v1.json"
FL3_DISCOVERY_BATTERY_RESULT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_DISCOVERY_BATTERY_RESULT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "result_id",
    "battery_id",
    "anchor_set_id",
    "adapter_id",
    "adapter_version",
    "job_id",
    "axis_scores",
    "canary_pass",
    "role_drift_flag",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "result_id"}

_AXES = (
    "reasoning_depth",
    "transfer_capacity",
    "coherence_under_pressure",
    "self_correction",
    "epistemic_behavior",
    "novel_structure",
)


def _validate_axis_scores(obj: Any) -> None:
    axes = require_dict(obj, name="axis_scores")
    enforce_max_fields(axes, max_fields=16)
    require_keys(axes, required=set(_AXES))
    reject_unknown_keys(axes, allowed=set(_AXES))
    for k in _AXES:
        v = axes.get(k)
        if not isinstance(v, (int, float)) or v < 0.0 or v > 1.0:
            raise SchemaValidationError(f"axis_scores.{k} must be in [0,1] (fail-closed)")


def validate_fl3_discovery_battery_result(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 discovery battery result")
    enforce_max_fields(entry, max_fields=32)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_DISCOVERY_BATTERY_RESULT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_DISCOVERY_BATTERY_RESULT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    for k in ("result_id", "battery_id", "anchor_set_id", "job_id"):
        validate_hex_64(entry, k)
    if not isinstance(entry.get("adapter_id"), str) or not str(entry.get("adapter_id")).strip():
        raise SchemaValidationError("adapter_id must be non-empty string (fail-closed)")
    if not isinstance(entry.get("adapter_version"), str) or not str(entry.get("adapter_version")).strip():
        raise SchemaValidationError("adapter_version must be non-empty string (fail-closed)")

    _validate_axis_scores(entry.get("axis_scores"))

    for k in ("canary_pass", "role_drift_flag"):
        if not isinstance(entry.get(k), bool):
            raise SchemaValidationError(f"{k} must be bool (fail-closed)")

    validate_created_at_utc_z(entry.get("created_at"))

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("result_id") != expected:
        raise SchemaValidationError("result_id mismatch vs canonical hash surface (fail-closed)")

