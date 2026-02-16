from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_canonical_json_bytes,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_bounded_json_value,
    validate_hex_64,
    validate_short_string,
)
from schemas.fl3_schema_common import ensure_sorted_str_list, sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_AXIS_SCORING_POLICY_SCHEMA_ID = "kt.axis_scoring_policy.v1"
FL3_AXIS_SCORING_POLICY_SCHEMA_FILE = "fl3/kt.axis_scoring_policy.v1.json"
FL3_AXIS_SCORING_POLICY_SCHEMA_VERSION_HASH = schema_version_hash(FL3_AXIS_SCORING_POLICY_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "axis_scoring_policy_id",
    "axes",
    "verdict_thresholds",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {"notes"}
_HASH_DROP_KEYS = {"created_at", "axis_scoring_policy_id"}

_AXIS_REQUIRED = {"axis_id", "gate_validator_ids", "soft_validator_weights", "aggregator"}
_AXIS_ALLOWED = set(_AXIS_REQUIRED)


def _validate_axis_entry(row: Dict[str, Any]) -> Dict[str, Any]:
    enforce_max_fields(row, max_fields=32)
    require_keys(row, required=_AXIS_REQUIRED)
    reject_unknown_keys(row, allowed=_AXIS_ALLOWED)

    axis_id = str(row.get("axis_id", "")).strip()
    if not axis_id:
        raise SchemaValidationError("axis_id must be non-empty (fail-closed)")
    validate_short_string({"axis_id": axis_id}, "axis_id", max_len=64)
    row["axis_id"] = axis_id

    gate_ids = row.get("gate_validator_ids", [])
    if gate_ids is None:
        gate_ids = []
    if gate_ids:
        row["gate_validator_ids"] = ensure_sorted_str_list(gate_ids, field="gate_validator_ids")
    else:
        row["gate_validator_ids"] = []

    soft = row.get("soft_validator_weights")
    if not isinstance(soft, list) or not soft:
        raise SchemaValidationError("soft_validator_weights must be non-empty list (fail-closed)")
    out_soft: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    order: List[str] = []
    for item in soft:
        s = require_dict(item, name="soft_validator_weights[]")
        enforce_max_fields(s, max_fields=4)
        require_keys(s, required={"validator_id", "weight"})
        reject_unknown_keys(s, allowed={"validator_id", "weight"})
        vid = str(s.get("validator_id", "")).strip()
        if not vid:
            raise SchemaValidationError("soft validator_id must be non-empty (fail-closed)")
        validate_short_string({"validator_id": vid}, "validator_id", max_len=128)
        if vid in seen:
            raise SchemaValidationError("duplicate soft validator_id (fail-closed)")
        seen.add(vid)
        w = s.get("weight")
        if not isinstance(w, (int, float)) or float(w) <= 0.0:
            raise SchemaValidationError("soft weight must be number >0 (fail-closed)")
        out_soft.append({"validator_id": vid, "weight": float(w)})
        order.append(vid)
    if order != sorted(order):
        raise SchemaValidationError("soft_validator_weights must be sorted by validator_id (fail-closed)")
    row["soft_validator_weights"] = out_soft

    agg = str(row.get("aggregator", "")).strip().upper()
    if agg not in {"MEAN", "TRIMMED_MEAN_5"}:
        raise SchemaValidationError("aggregator invalid (fail-closed)")
    row["aggregator"] = agg
    return row


def _validate_threshold_map(value: Any, *, axis_ids: Set[str], name: str) -> Dict[str, float]:
    d = require_dict(value, name=name)
    enforce_max_fields(d, max_fields=64)
    validate_bounded_json_value(d, max_depth=2, max_string_len=128, max_list_len=0)
    out: Dict[str, float] = {}
    for k, v in d.items():
        axis_id = str(k).strip()
        if axis_id not in axis_ids:
            raise SchemaValidationError(f"{name} contains unknown axis_id (fail-closed): {axis_id!r}")
        if not isinstance(v, (int, float)):
            raise SchemaValidationError(f"{name} values must be numbers (fail-closed)")
        f = float(v)
        if f < 0.0 or f > 1.0:
            raise SchemaValidationError(f"{name} values must be in [0,1] (fail-closed)")
        out[axis_id] = f
    missing = sorted(axis_ids - set(out.keys()))
    if missing:
        raise SchemaValidationError(f"{name} missing thresholds for axes (fail-closed): {missing}")
    return {k: out[k] for k in sorted(out.keys())}


def validate_fl3_axis_scoring_policy(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="axis_scoring_policy")
    enforce_max_fields(entry, max_fields=128)
    enforce_max_canonical_json_bytes(entry, max_bytes=256_000)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_AXIS_SCORING_POLICY_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_AXIS_SCORING_POLICY_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "axis_scoring_policy_id")
    validate_created_at_utc_z(entry.get("created_at"))
    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    axes_val = entry.get("axes")
    if not isinstance(axes_val, list) or not axes_val:
        raise SchemaValidationError("axes must be non-empty list (fail-closed)")
    axes: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    order: List[str] = []
    for item in axes_val:
        row = require_dict(item, name="axes[]")
        row = _validate_axis_entry(row)
        axis_id = str(row["axis_id"])
        if axis_id in seen:
            raise SchemaValidationError("duplicate axis_id (fail-closed)")
        seen.add(axis_id)
        axes.append(row)
        order.append(axis_id)
    if order != sorted(order):
        raise SchemaValidationError("axes must be sorted by axis_id (fail-closed)")
    entry["axes"] = axes
    axis_ids = set(order)

    vt = require_dict(entry.get("verdict_thresholds"), name="verdict_thresholds")
    enforce_max_fields(vt, max_fields=8)
    require_keys(vt, required={"promote_min", "hold_min", "quarantine_on_gate_fail"})
    reject_unknown_keys(vt, allowed={"promote_min", "hold_min", "quarantine_on_gate_fail"})
    promote_min = _validate_threshold_map(vt.get("promote_min"), axis_ids=axis_ids, name="promote_min")
    hold_min = _validate_threshold_map(vt.get("hold_min"), axis_ids=axis_ids, name="hold_min")
    for ax in sorted(axis_ids):
        if float(hold_min[ax]) > float(promote_min[ax]):
            raise SchemaValidationError("hold_min must be <= promote_min per axis (fail-closed)")
    qgate = vt.get("quarantine_on_gate_fail")
    if not isinstance(qgate, bool):
        raise SchemaValidationError("quarantine_on_gate_fail must be boolean (fail-closed)")
    vt["promote_min"] = promote_min
    vt["hold_min"] = hold_min
    vt["quarantine_on_gate_fail"] = bool(qgate)
    entry["verdict_thresholds"] = vt

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("axis_scoring_policy_id") != expected:
        raise SchemaValidationError("axis_scoring_policy_id does not match canonical hash surface (fail-closed)")

