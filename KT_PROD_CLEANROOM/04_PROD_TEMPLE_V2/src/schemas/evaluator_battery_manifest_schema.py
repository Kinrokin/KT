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


EVALUATOR_BATTERY_MANIFEST_SCHEMA_ID = "kt.evaluator.battery_manifest.v1"
EVALUATOR_BATTERY_MANIFEST_SCHEMA_FILE = "kt.evaluator.battery_manifest.v1.json"
EVALUATOR_BATTERY_MANIFEST_SCHEMA_VERSION_HASH = schema_version_hash(EVALUATOR_BATTERY_MANIFEST_SCHEMA_FILE)

EVALUATOR_BATTERY_MANIFEST_REQUIRED_FIELDS_ORDER = (
    "schema_id",
    "schema_version_hash",
    "battery_id",
    "tests",
    "ordering",
    "pass_rule",
)

EVALUATOR_BATTERY_MANIFEST_REQUIRED_FIELDS: Set[str] = set(EVALUATOR_BATTERY_MANIFEST_REQUIRED_FIELDS_ORDER)
EVALUATOR_BATTERY_MANIFEST_ALLOWED_FIELDS: Set[str] = set(EVALUATOR_BATTERY_MANIFEST_REQUIRED_FIELDS_ORDER)


def validate_evaluator_battery_manifest(payload: Dict[str, Any]) -> None:
    require_dict(payload, name="Evaluator battery manifest")
    enforce_max_fields(payload, max_fields=16)
    require_keys(payload, required=EVALUATOR_BATTERY_MANIFEST_REQUIRED_FIELDS)
    reject_unknown_keys(payload, allowed=EVALUATOR_BATTERY_MANIFEST_ALLOWED_FIELDS)

    validate_short_string(payload, "schema_id", max_len=64)
    validate_hex_64(payload, "schema_version_hash")
    validate_short_string(payload, "battery_id", max_len=128)

    if payload["schema_id"] != EVALUATOR_BATTERY_MANIFEST_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if payload["schema_version_hash"] != EVALUATOR_BATTERY_MANIFEST_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    tests = payload.get("tests")
    if not isinstance(tests, list) or not tests:
        raise SchemaValidationError("tests must be a non-empty list (fail-closed)")
    if not all(isinstance(x, str) and x.strip() for x in tests):
        raise SchemaValidationError("tests must contain non-empty strings (fail-closed)")
    if tests != sorted(tests):
        raise SchemaValidationError("tests must be sorted lexicographically (fail-closed)")
    if len(set(tests)) != len(tests):
        raise SchemaValidationError("tests must not contain duplicates (fail-closed)")

    if payload.get("ordering") != "stable":
        raise SchemaValidationError("ordering must be 'stable' (fail-closed)")
    if payload.get("pass_rule") != "ALL_PASS":
        raise SchemaValidationError("pass_rule must be 'ALL_PASS' (fail-closed)")
