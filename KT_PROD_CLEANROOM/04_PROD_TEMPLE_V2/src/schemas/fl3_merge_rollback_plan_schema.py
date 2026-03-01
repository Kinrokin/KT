from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_hex_64,
    validate_short_string,
)
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_MERGE_ROLLBACK_PLAN_SCHEMA_ID = "kt.merge_rollback_plan.v1"
FL3_MERGE_ROLLBACK_PLAN_SCHEMA_FILE = "fl3/kt.merge_rollback_plan.v1.json"
FL3_MERGE_ROLLBACK_PLAN_SCHEMA_VERSION_HASH = schema_version_hash(FL3_MERGE_ROLLBACK_PLAN_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "rollback_plan_id",
    "merge_manifest_id",
    "steps",
    "created_at",
)
_OPTIONAL_ORDER = ("notes",)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)
_HASH_DROP_KEYS = {"created_at", "rollback_plan_id"}


def _validate_steps(value: Any) -> List[Dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise SchemaValidationError("steps must be non-empty list (fail-closed)")
    out: List[Dict[str, str]] = []
    for item in value:
        row = require_dict(item, name="steps[]")
        require_keys(row, required={"step_id", "action", "target"})
        reject_unknown_keys(row, allowed={"step_id", "action", "target"})
        step_id = str(row.get("step_id", "")).strip()
        action = str(row.get("action", "")).strip()
        target = str(row.get("target", "")).strip()
        if not step_id or not action or not target:
            raise SchemaValidationError("steps[].step_id/action/target must be non-empty (fail-closed)")
        validate_short_string({"step_id": step_id}, "step_id", max_len=128)
        validate_short_string({"action": action}, "action", max_len=256)
        validate_short_string({"target": target}, "target", max_len=512)
        out.append({"step_id": step_id, "action": action, "target": target})
    ids = [r["step_id"] for r in out]
    if ids != sorted(ids):
        raise SchemaValidationError("steps must be sorted by step_id (fail-closed)")
    if len(set(ids)) != len(ids):
        raise SchemaValidationError("steps step_id values must be unique (fail-closed)")
    return out


def validate_fl3_merge_rollback_plan(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="merge_rollback_plan")
    enforce_max_fields(entry, max_fields=256)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_MERGE_ROLLBACK_PLAN_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_MERGE_ROLLBACK_PLAN_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "rollback_plan_id")
    validate_hex_64(entry, "merge_manifest_id")
    validate_created_at_utc_z(entry.get("created_at"))

    _ = _validate_steps(entry.get("steps"))

    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("rollback_plan_id") != expected:
        raise SchemaValidationError("rollback_plan_id does not match canonical hash surface (fail-closed)")


