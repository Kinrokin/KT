from __future__ import annotations

from typing import Any, Dict, Set

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
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_AXIS_FITNESS_REPORT_SCHEMA_ID = "kt.axis_fitness_report.v1"
FL3_AXIS_FITNESS_REPORT_SCHEMA_FILE = "fl3/kt.axis_fitness_report.v1.json"
FL3_AXIS_FITNESS_REPORT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_AXIS_FITNESS_REPORT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "axis_fitness_report_id",
    "suite_eval_report_id",
    "axis_scoring_policy_id",
    "decision",
    "axis_scores",
    "hard_gate_pass",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {"notes"}
_HASH_DROP_KEYS = {"created_at", "axis_fitness_report_id"}


def validate_fl3_axis_fitness_report(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="axis_fitness_report")
    enforce_max_fields(entry, max_fields=128)
    enforce_max_canonical_json_bytes(entry, max_bytes=256_000)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_AXIS_FITNESS_REPORT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_AXIS_FITNESS_REPORT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    for f in ("axis_fitness_report_id", "suite_eval_report_id", "axis_scoring_policy_id"):
        validate_hex_64(entry, f)

    decision = str(entry.get("decision", "")).strip().upper()
    if decision not in {"PROMOTE", "HOLD", "QUARANTINE"}:
        raise SchemaValidationError("decision invalid (fail-closed)")
    entry["decision"] = decision

    axis_scores = require_dict(entry.get("axis_scores"), name="axis_scores")
    enforce_max_fields(axis_scores, max_fields=64)
    validate_bounded_json_value(axis_scores, max_depth=2, max_string_len=64, max_list_len=0)
    for k, v in axis_scores.items():
        axis_id = str(k).strip()
        if not axis_id:
            raise SchemaValidationError("axis_scores contains empty axis_id (fail-closed)")
        validate_short_string({"axis_id": axis_id}, "axis_id", max_len=64)
        if not isinstance(v, (int, float)):
            raise SchemaValidationError("axis_scores values must be numbers (fail-closed)")
        fval = float(v)
        if fval < 0.0 or fval > 1.0:
            raise SchemaValidationError("axis_scores values must be in [0,1] (fail-closed)")
        axis_scores[axis_id] = fval
    entry["axis_scores"] = {k: axis_scores[k] for k in sorted(axis_scores.keys())}

    hgp = entry.get("hard_gate_pass")
    if not isinstance(hgp, bool):
        raise SchemaValidationError("hard_gate_pass must be boolean (fail-closed)")
    entry["hard_gate_pass"] = bool(hgp)

    validate_created_at_utc_z(entry.get("created_at"))
    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("axis_fitness_report_id") != expected:
        raise SchemaValidationError("axis_fitness_report_id does not match canonical hash surface (fail-closed)")

