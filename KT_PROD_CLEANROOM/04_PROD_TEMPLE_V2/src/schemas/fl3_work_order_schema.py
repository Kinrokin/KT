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
    validate_short_string,
)
from schemas.schema_files import schema_version_hash


FL3_WORK_ORDER_SCHEMA_ID = "kt.work_order.v1"
FL3_WORK_ORDER_SCHEMA_FILE = "fl3/kt.work_order.v1.json"
FL3_WORK_ORDER_SCHEMA_VERSION_HASH = schema_version_hash(FL3_WORK_ORDER_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "work_order_id",
    "title",
    "mission",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {
    "role_contract",
    "truth_pins",
    "absolute_constraints",
    "definition_of_done",
    "run_root_protocol",
    "single_source_of_truth_harness",
    "epic_execution_protocol",
    "closure_queue",
    "commands_playbook",
    "deliverable_packaging",
    "final_output_contract",
}


def validate_fl3_work_order(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="work_order")
    enforce_max_fields(entry, max_fields=128)
    enforce_max_canonical_json_bytes(entry, max_bytes=512 * 1024)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    validate_bounded_json_value(entry, max_depth=10, max_string_len=32_768, max_list_len=2048)

    if entry.get("schema_id") != FL3_WORK_ORDER_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_WORK_ORDER_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_short_string(entry, "work_order_id", max_len=256)
    validate_short_string(entry, "title", max_len=512)
    validate_short_string(entry, "mission", max_len=16_384)

    for k in (
        "role_contract",
        "truth_pins",
        "absolute_constraints",
        "definition_of_done",
        "run_root_protocol",
        "single_source_of_truth_harness",
        "epic_execution_protocol",
        "commands_playbook",
        "deliverable_packaging",
        "final_output_contract",
    ):
        if k in entry and not isinstance(entry.get(k), dict):
            raise SchemaValidationError(f"{k} must be an object (fail-closed)")
    if "closure_queue" in entry and not isinstance(entry.get("closure_queue"), list):
        raise SchemaValidationError("closure_queue must be a list (fail-closed)")

