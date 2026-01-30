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


FL3_COGNITIVE_FITNESS_V2_SCHEMA_ID = "kt.cognitive_fitness.v2"
FL3_COGNITIVE_FITNESS_V2_SCHEMA_FILE = "fl3/kt.cognitive_fitness.v2.json"
FL3_COGNITIVE_FITNESS_V2_SCHEMA_VERSION_HASH = schema_version_hash(FL3_COGNITIVE_FITNESS_V2_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "fitness_id",
    "adapter_id",
    "adapter_version",
    "job_id",
    "axes",
    "promotion_verdict",
    "canary_pass",
    "role_id",
    "role_drift_flag",
    "evidence",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "fitness_id"}

_AXES = (
    "reasoning_depth",
    "transfer_capacity",
    "coherence_under_pressure",
    "self_correction",
    "epistemic_behavior",
    "novel_structure",
)


def _validate_axis(obj: Any) -> None:
    axis = require_dict(obj, name="axis")
    enforce_max_fields(axis, max_fields=8)
    require_keys(axis, required={"raw_score", "anchor_delta", "normalized_score"})
    reject_unknown_keys(axis, allowed={"raw_score", "anchor_delta", "normalized_score"})
    raw = axis.get("raw_score")
    delta = axis.get("anchor_delta")
    norm = axis.get("normalized_score")
    if not isinstance(raw, (int, float)) or raw < 0.0 or raw > 1.0:
        raise SchemaValidationError("raw_score must be in [0,1] (fail-closed)")
    if not isinstance(delta, (int, float)) or delta < -1.0 or delta > 1.0:
        raise SchemaValidationError("anchor_delta must be in [-1,1] (fail-closed)")
    if not isinstance(norm, (int, float)) or norm < 0.0 or norm > 1.0:
        raise SchemaValidationError("normalized_score must be in [0,1] (fail-closed)")


def _validate_axes(obj: Any) -> None:
    axes = require_dict(obj, name="axes")
    enforce_max_fields(axes, max_fields=16)
    require_keys(axes, required=set(_AXES))
    reject_unknown_keys(axes, allowed=set(_AXES))
    for k in _AXES:
        _validate_axis(axes.get(k))


def _validate_evidence(obj: Any) -> None:
    ev = require_dict(obj, name="evidence")
    enforce_max_fields(ev, max_fields=16)
    require_keys(ev, required={"anchor_set_id", "battery_id", "battery_result_id", "role_spec_id", "evidence_hashes"})
    reject_unknown_keys(ev, allowed={"anchor_set_id", "battery_id", "battery_result_id", "role_spec_id", "evidence_hashes"})
    for k in ("anchor_set_id", "battery_id", "battery_result_id", "role_spec_id"):
        validate_hex_64(ev, k)
    eh = require_dict(ev.get("evidence_hashes"), name="evidence_hashes")
    enforce_max_fields(eh, max_fields=16)
    require_keys(eh, required={"battery_bundle_hash", "anchor_eval_hash", "trace_replay_hash"})
    reject_unknown_keys(eh, allowed={"battery_bundle_hash", "anchor_eval_hash", "trace_replay_hash"})
    for k in ("battery_bundle_hash", "anchor_eval_hash", "trace_replay_hash"):
        validate_hex_64(eh, k)


def validate_fl3_cognitive_fitness_v2(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 cognitive fitness v2")
    enforce_max_fields(entry, max_fields=64)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_COGNITIVE_FITNESS_V2_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_COGNITIVE_FITNESS_V2_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "fitness_id")
    validate_hex_64(entry, "job_id")
    if not isinstance(entry.get("adapter_id"), str) or not str(entry.get("adapter_id")).strip():
        raise SchemaValidationError("adapter_id must be non-empty string (fail-closed)")
    if not isinstance(entry.get("adapter_version"), str) or not str(entry.get("adapter_version")).strip():
        raise SchemaValidationError("adapter_version must be non-empty string (fail-closed)")
    if not isinstance(entry.get("role_id"), str) or not str(entry.get("role_id")).strip():
        raise SchemaValidationError("role_id must be non-empty string (fail-closed)")

    _validate_axes(entry.get("axes"))
    _validate_evidence(entry.get("evidence"))

    if not isinstance(entry.get("canary_pass"), bool):
        raise SchemaValidationError("canary_pass must be bool (fail-closed)")
    if not isinstance(entry.get("role_drift_flag"), bool):
        raise SchemaValidationError("role_drift_flag must be bool (fail-closed)")
    verdict = entry.get("promotion_verdict")
    if verdict not in {"PROMOTE", "SHADOW", "QUARANTINE", "HALT"}:
        raise SchemaValidationError("promotion_verdict invalid (fail-closed)")

    validate_created_at_utc_z(entry.get("created_at"))

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("fitness_id") != expected:
        raise SchemaValidationError("fitness_id mismatch vs canonical hash surface (fail-closed)")

