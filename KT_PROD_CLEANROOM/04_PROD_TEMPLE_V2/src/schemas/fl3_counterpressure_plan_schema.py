from __future__ import annotations

from typing import Any, Dict, Set

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


FL3_COUNTERPRESSURE_PLAN_SCHEMA_ID = "kt.counterpressure_plan.v1"
FL3_COUNTERPRESSURE_PLAN_SCHEMA_FILE = "fl3/kt.counterpressure_plan.v1.json"
FL3_COUNTERPRESSURE_PLAN_SCHEMA_VERSION_HASH = schema_version_hash(FL3_COUNTERPRESSURE_PLAN_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "counterpressure_plan_id",
    "base_model_id",
    "optimization_suite_id",
    "optimization_suite_root_hash",
    "adversarial_suite_id",
    "adversarial_suite_root_hash",
    "decode_policy_id",
    "decode_cfg_hash",
    "break_hypothesis_id",
    "required_probe_families",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {"notes"}
_HASH_DROP_KEYS = {"created_at", "counterpressure_plan_id"}


def validate_fl3_counterpressure_plan(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 counterpressure plan v1")
    enforce_max_fields(entry, max_fields=64)
    enforce_max_canonical_json_bytes(entry, max_bytes=128_000)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_COUNTERPRESSURE_PLAN_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_COUNTERPRESSURE_PLAN_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "counterpressure_plan_id")
    validate_short_string(entry, "base_model_id", max_len=128)

    validate_short_string(entry, "optimization_suite_id", max_len=128)
    validate_hex_64(entry, "optimization_suite_root_hash")
    validate_short_string(entry, "adversarial_suite_id", max_len=128)
    validate_hex_64(entry, "adversarial_suite_root_hash")

    validate_short_string(entry, "decode_policy_id", max_len=128)
    validate_hex_64(entry, "decode_cfg_hash")
    validate_hex_64(entry, "break_hypothesis_id")
    validate_created_at_utc_z(entry.get("created_at"))

    entry["required_probe_families"] = ensure_sorted_str_list(entry.get("required_probe_families"), field="required_probe_families")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("counterpressure_plan_id") != expected:
        raise SchemaValidationError("counterpressure_plan_id does not match canonical hash surface (fail-closed)")

