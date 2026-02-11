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
from schemas.schema_files import schema_version_hash


EVALUATOR_RESULT_SCHEMA_ID = "kt.evaluator.result.v1"
EVALUATOR_RESULT_SCHEMA_FILE = "kt.evaluator.result.v1.json"
EVALUATOR_RESULT_SCHEMA_VERSION_HASH = schema_version_hash(EVALUATOR_RESULT_SCHEMA_FILE)

EVALUATOR_RESULT_REQUIRED_FIELDS_ORDER = (
    "schema_id",
    "schema_version_hash",
    "adapter_id",
    "adapter_version",
    "battery_id",
    "results",
    "final_verdict",
)

EVALUATOR_RESULT_REQUIRED_FIELDS: Set[str] = set(EVALUATOR_RESULT_REQUIRED_FIELDS_ORDER)
EVALUATOR_RESULT_ALLOWED_FIELDS: Set[str] = set(EVALUATOR_RESULT_REQUIRED_FIELDS_ORDER)


def validate_evaluator_result(payload: Dict[str, Any]) -> None:
    require_dict(payload, name="Evaluator result")
    enforce_max_fields(payload, max_fields=16)
    require_keys(payload, required=EVALUATOR_RESULT_REQUIRED_FIELDS)
    reject_unknown_keys(payload, allowed=EVALUATOR_RESULT_ALLOWED_FIELDS)

    validate_short_string(payload, "schema_id", max_len=64)
    validate_hex_64(payload, "schema_version_hash")
    validate_short_string(payload, "adapter_id", max_len=128)
    validate_short_string(payload, "adapter_version", max_len=64)
    validate_short_string(payload, "battery_id", max_len=128)

    if payload["schema_id"] != EVALUATOR_RESULT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if payload["schema_version_hash"] != EVALUATOR_RESULT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    results = payload.get("results")
    if not isinstance(results, dict):
        raise SchemaValidationError("results must be an object (fail-closed)")
    for k, v in results.items():
        if not isinstance(k, str) or not k.strip():
            raise SchemaValidationError("results keys must be non-empty strings (fail-closed)")
        if not isinstance(v, str) or not v.strip():
            raise SchemaValidationError("results values must be non-empty strings (fail-closed)")

    if payload.get("final_verdict") not in {"PASS", "FAIL"}:
        raise SchemaValidationError("final_verdict must be PASS or FAIL (fail-closed)")
