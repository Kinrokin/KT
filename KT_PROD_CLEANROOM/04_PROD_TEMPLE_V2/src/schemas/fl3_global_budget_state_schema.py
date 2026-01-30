from __future__ import annotations

import re
from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64
from schemas.fl3_schema_common import validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_GLOBAL_BUDGET_STATE_SCHEMA_ID = "kt.global_budget_state.v1"
FL3_GLOBAL_BUDGET_STATE_SCHEMA_FILE = "fl3/kt.global_budget_state.v1.json"
FL3_GLOBAL_BUDGET_STATE_SCHEMA_VERSION_HASH = schema_version_hash(FL3_GLOBAL_BUDGET_STATE_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "day_utc",
    "gpu_hours_used",
    "jobs_run",
    "lock_state",
    "last_t1_failure",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)

_DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def validate_fl3_global_budget_state(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 global budget state")
    enforce_max_fields(entry, max_fields=32)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_GLOBAL_BUDGET_STATE_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_GLOBAL_BUDGET_STATE_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")
    validate_hex_64(entry, "schema_version_hash")

    day = entry.get("day_utc")
    if not isinstance(day, str) or not _DAY_RE.match(day):
        raise SchemaValidationError("day_utc must be YYYY-MM-DD (fail-closed)")

    gpu = entry.get("gpu_hours_used")
    if not isinstance(gpu, (int, float)) or gpu < 0:
        raise SchemaValidationError("gpu_hours_used must be >= 0 (fail-closed)")

    jobs = entry.get("jobs_run")
    if not isinstance(jobs, int) or jobs < 0:
        raise SchemaValidationError("jobs_run must be >= 0 integer (fail-closed)")

    lock_state = entry.get("lock_state")
    if lock_state not in {"OPEN", "LOCKED"}:
        raise SchemaValidationError("lock_state must be OPEN or LOCKED (fail-closed)")

    last = entry.get("last_t1_failure")
    if last is not None and (not isinstance(last, str) or not last.strip()):
        raise SchemaValidationError("last_t1_failure must be null or non-empty string (fail-closed)")

