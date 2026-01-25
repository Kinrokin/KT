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


TASK_CONTEXT_SCHEMA_ID = "kt.task_context.v1"
TASK_CONTEXT_SCHEMA_FILE = "kt.task_context.v1.json"
TASK_CONTEXT_SCHEMA_VERSION_HASH = schema_version_hash(TASK_CONTEXT_SCHEMA_FILE)

TASK_CONTEXT_REQUIRED_FIELDS_ORDER = (
    "schema_id",
    "schema_version_hash",
    "task_id",
    "domain_tags",
    "risk_class",
    "constraints",
    "epoch_context",
    "input_refs",
)

TASK_CONTEXT_REQUIRED_FIELDS: Set[str] = set(TASK_CONTEXT_REQUIRED_FIELDS_ORDER)
TASK_CONTEXT_ALLOWED_FIELDS: Set[str] = set(TASK_CONTEXT_REQUIRED_FIELDS_ORDER)


def validate_task_context(payload: Dict[str, Any]) -> None:
    require_dict(payload, name="Task context")
    enforce_max_fields(payload, max_fields=24)
    require_keys(payload, required=TASK_CONTEXT_REQUIRED_FIELDS)
    reject_unknown_keys(payload, allowed=TASK_CONTEXT_ALLOWED_FIELDS)

    validate_short_string(payload, "schema_id", max_len=64)
    validate_hex_64(payload, "schema_version_hash")
    validate_hex_64(payload, "task_id")

    if payload["schema_id"] != TASK_CONTEXT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if payload["schema_version_hash"] != TASK_CONTEXT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    _validate_string_list(payload.get("domain_tags"), "domain_tags")
    _validate_string_list(payload.get("constraints"), "constraints")
    _validate_string_list(payload.get("input_refs"), "input_refs")

    risk_class = payload.get("risk_class")
    if risk_class not in {"LOW", "MEDIUM", "HIGH"}:
        raise SchemaValidationError("risk_class must be LOW, MEDIUM, or HIGH")

    epoch = require_dict(payload.get("epoch_context"), name="epoch_context")
    require_keys(epoch, required={"epoch_id", "profile"})
    reject_unknown_keys(epoch, allowed={"epoch_id", "profile"})
    validate_short_string(epoch, "epoch_id", max_len=128)
    validate_short_string(epoch, "profile", max_len=64)


def _validate_string_list(value: Any, name: str) -> None:
    if not isinstance(value, list):
        raise SchemaValidationError(f"{name} must be a list (fail-closed)")
    if not all(isinstance(x, str) and x.strip() for x in value):
        raise SchemaValidationError(f"{name} must contain non-empty strings (fail-closed)")
