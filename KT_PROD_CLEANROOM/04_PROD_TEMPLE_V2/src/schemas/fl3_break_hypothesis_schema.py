from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_canonical_json_bytes,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_hex_64,
    validate_short_string,
)
from schemas.fl3_schema_common import ensure_sorted_str_list, sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_BREAK_HYPOTHESIS_SCHEMA_ID = "kt.break_hypothesis.v1"
FL3_BREAK_HYPOTHESIS_SCHEMA_FILE = "fl3/kt.break_hypothesis.v1.json"
FL3_BREAK_HYPOTHESIS_SCHEMA_VERSION_HASH = schema_version_hash(FL3_BREAK_HYPOTHESIS_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "break_hypothesis_id",
    "base_model_id",
    "suite_id",
    "hypothesis",
    "predicted_failure_modes",
    "required_probe_families",
    "regression_budgets",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {"notes"}
_HASH_DROP_KEYS = {"created_at", "break_hypothesis_id"}


def _validate_failure_modes(value: Any) -> List[Dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise SchemaValidationError("predicted_failure_modes must be a non-empty list (fail-closed)")
    out: List[Dict[str, str]] = []
    order: List[Tuple[str, str]] = []
    for item in value:
        d = require_dict(item, name="predicted_failure_modes[]")
        enforce_max_fields(d, max_fields=4)
        require_keys(d, required={"mode_id", "description"})
        reject_unknown_keys(d, allowed={"mode_id", "description"})
        mode_id = str(d.get("mode_id", "")).strip()
        desc = str(d.get("description", "")).strip()
        if not mode_id or not desc:
            raise SchemaValidationError("predicted_failure_modes entries must be non-empty (fail-closed)")
        validate_short_string({"mode_id": mode_id}, "mode_id", max_len=64)
        validate_short_string({"description": desc}, "description", max_len=800)
        out.append({"mode_id": mode_id, "description": desc})
        order.append((mode_id, desc))
    if order != sorted(order):
        raise SchemaValidationError("predicted_failure_modes must be sorted by (mode_id, description) (fail-closed)")
    return out


def validate_fl3_break_hypothesis(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 break hypothesis v1")
    enforce_max_fields(entry, max_fields=64)
    enforce_max_canonical_json_bytes(entry, max_bytes=128_000)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_BREAK_HYPOTHESIS_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_BREAK_HYPOTHESIS_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "break_hypothesis_id")
    validate_short_string(entry, "base_model_id", max_len=128)
    validate_short_string(entry, "suite_id", max_len=128)
    validate_short_string(entry, "hypothesis", max_len=2000)
    validate_created_at_utc_z(entry.get("created_at"))

    entry["predicted_failure_modes"] = _validate_failure_modes(entry.get("predicted_failure_modes"))
    entry["required_probe_families"] = ensure_sorted_str_list(entry.get("required_probe_families"), field="required_probe_families")

    budgets = require_dict(entry.get("regression_budgets"), name="regression_budgets")
    enforce_max_fields(budgets, max_fields=8)
    require_keys(budgets, required={"safety_regression_epsilon", "new_hard_failures_allowed"})
    reject_unknown_keys(budgets, allowed={"safety_regression_epsilon", "new_hard_failures_allowed"})

    eps = budgets.get("safety_regression_epsilon")
    if not isinstance(eps, (int, float)):
        raise SchemaValidationError("safety_regression_epsilon must be a number (fail-closed)")
    if float(eps) < 0.0:
        raise SchemaValidationError("safety_regression_epsilon must be >=0 (fail-closed)")
    budgets["safety_regression_epsilon"] = float(eps)

    nhf = budgets.get("new_hard_failures_allowed")
    if not isinstance(nhf, int) or nhf < 0:
        raise SchemaValidationError("new_hard_failures_allowed must be an integer >=0 (fail-closed)")
    budgets["new_hard_failures_allowed"] = int(nhf)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("break_hypothesis_id") != expected:
        raise SchemaValidationError("break_hypothesis_id does not match canonical hash surface (fail-closed)")

