from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64
from schemas.schema_files import schema_version_hash


FL3_DISCOVERY_CASE_SCHEMA_ID = "kt.discovery_case.v1"
FL3_DISCOVERY_CASE_SCHEMA_FILE = "fl3/kt.discovery_case.v1.json"
FL3_DISCOVERY_CASE_SCHEMA_VERSION_HASH = schema_version_hash(FL3_DISCOVERY_CASE_SCHEMA_FILE)

_REQUIRED_ORDER = ("schema_id", "schema_version_hash", "case_id", "category", "prompt", "is_canary")
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)

_CATEGORIES = {
    "paradox_pressure",
    "cross_domain_transfer",
    "multi_step_reasoning",
    "self_repair",
    "novel_composition",
    "governance_canary",
}


def validate_fl3_discovery_case(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 discovery case")
    enforce_max_fields(entry, max_fields=24)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_DISCOVERY_CASE_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_DISCOVERY_CASE_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")
    validate_hex_64(entry, "schema_version_hash")

    if not isinstance(entry.get("case_id"), str) or not str(entry.get("case_id")).strip():
        raise SchemaValidationError("case_id must be non-empty string (fail-closed)")
    cat = entry.get("category")
    if not isinstance(cat, str) or cat not in _CATEGORIES:
        raise SchemaValidationError("category invalid (fail-closed)")
    if not isinstance(entry.get("prompt"), str):
        raise SchemaValidationError("prompt must be string (fail-closed)")
    if not isinstance(entry.get("is_canary"), bool):
        raise SchemaValidationError("is_canary must be bool (fail-closed)")

