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


ADAPTER_ENTRY_SCHEMA_ID = "kt.runtime.adapter_entry.v1"
ADAPTER_ENTRY_SCHEMA_FILE = "kt.runtime.adapter_entry.v1.json"
ADAPTER_ENTRY_SCHEMA_VERSION_HASH = schema_version_hash(ADAPTER_ENTRY_SCHEMA_FILE)

ADAPTER_ENTRY_REQUIRED_FIELDS_ORDER = (
    "schema_id",
    "schema_version_hash",
    "adapter_id",
    "version",
    "base_model",
    "artifact_path",
    "artifact_hash",
    "capabilities",
    "constraints",
    "training_receipt_ref",
    "evaluation_receipt_ref",
    "status",
)

ADAPTER_ENTRY_REQUIRED_FIELDS: Set[str] = set(ADAPTER_ENTRY_REQUIRED_FIELDS_ORDER)
ADAPTER_ENTRY_ALLOWED_FIELDS: Set[str] = set(ADAPTER_ENTRY_REQUIRED_FIELDS_ORDER)


def validate_adapter_entry(entry: Dict[str, Any]) -> None:
    require_dict(entry, name="Adapter entry")
    enforce_max_fields(entry, max_fields=24)
    require_keys(entry, required=ADAPTER_ENTRY_REQUIRED_FIELDS)
    reject_unknown_keys(entry, allowed=ADAPTER_ENTRY_ALLOWED_FIELDS)

    validate_short_string(entry, "schema_id", max_len=64)
    validate_hex_64(entry, "schema_version_hash")
    validate_short_string(entry, "adapter_id", max_len=128)
    validate_short_string(entry, "version", max_len=64)
    validate_short_string(entry, "base_model", max_len=128)
    validate_short_string(entry, "artifact_path", max_len=512)
    validate_hex_64(entry, "artifact_hash")
    validate_short_string(entry, "training_receipt_ref", max_len=256)
    validate_short_string(entry, "evaluation_receipt_ref", max_len=256)

    if entry["schema_id"] != ADAPTER_ENTRY_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry["schema_version_hash"] != ADAPTER_ENTRY_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    if entry.get("status") not in {"ACTIVE", "DEPRECATED", "REVOKED"}:
        raise SchemaValidationError("status must be ACTIVE, DEPRECATED, or REVOKED")

    _validate_string_list(entry.get("capabilities"), "capabilities")
    _validate_string_list(entry.get("constraints"), "constraints")


def _validate_string_list(value: Any, name: str) -> None:
    if not isinstance(value, list) or not all(isinstance(x, str) and x.strip() for x in value):
        raise SchemaValidationError(f"{name} must be a list of non-empty strings")
