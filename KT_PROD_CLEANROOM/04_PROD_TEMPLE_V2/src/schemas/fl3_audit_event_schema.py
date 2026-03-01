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
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_AUDIT_EVENT_SCHEMA_ID = "kt.audit_event.v1"
FL3_AUDIT_EVENT_SCHEMA_FILE = "fl3/kt.audit_event.v1.json"
FL3_AUDIT_EVENT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_AUDIT_EVENT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "event_id",
    "run_id",
    "lane_id",
    "event_kind",
    "severity",
    "reason_codes",
    "component",
    "summary",
    "evidence_paths",
    "created_at",
)
_OPTIONAL_ORDER = ("notes",)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)


def _validate_sorted_string_list(value: Any, *, field: str, max_len: int) -> None:
    if not isinstance(value, list):
        raise SchemaValidationError(f"{field} must be a list (fail-closed)")
    if not value:
        raise SchemaValidationError(f"{field} must be non-empty list (fail-closed)")
    stripped = []
    for x in value:
        if not isinstance(x, str) or not x.strip():
            raise SchemaValidationError(f"{field} must contain non-empty strings (fail-closed)")
        s = x.strip()
        if len(s) > max_len:
            raise SchemaValidationError(f"{field} entry too long (fail-closed)")
        stripped.append(s)
    if stripped != sorted(stripped):
        raise SchemaValidationError(f"{field} must be sorted (fail-closed)")


def validate_fl3_audit_event(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 audit event")
    enforce_max_fields(entry, max_fields=32)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    enforce_max_canonical_json_bytes(entry, max_bytes=256 * 1024)

    if entry.get("schema_id") != FL3_AUDIT_EVENT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_AUDIT_EVENT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "event_id")

    validate_short_string(entry, "run_id", max_len=128)
    validate_short_string(entry, "lane_id", max_len=64)
    validate_short_string(entry, "event_kind", max_len=64)
    validate_short_string(entry, "component", max_len=128)
    validate_short_string(entry, "summary", max_len=8192)
    validate_created_at_utc_z(entry.get("created_at"))

    if entry.get("severity") not in {"INFO", "WARN", "FAIL", "FAIL_CLOSED", "CONTAMINATED"}:
        raise SchemaValidationError("severity invalid (fail-closed)")

    _validate_sorted_string_list(entry.get("reason_codes"), field="reason_codes", max_len=128)
    evidence_paths = entry.get("evidence_paths")
    if not isinstance(evidence_paths, list):
        raise SchemaValidationError("evidence_paths must be a list (fail-closed)")
    # evidence_paths may be empty but must be sorted and clean strings.
    stripped = []
    for x in evidence_paths:
        if not isinstance(x, str) or not x.strip():
            raise SchemaValidationError("evidence_paths must contain non-empty strings (fail-closed)")
        s = x.strip()
        if len(s) > 2048:
            raise SchemaValidationError("evidence_paths entry too long (fail-closed)")
        stripped.append(s)
    if stripped != sorted(stripped):
        raise SchemaValidationError("evidence_paths must be sorted (fail-closed)")

    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    expected_id = sha256_hex_of_obj(entry, drop_keys={"created_at", "event_id"})
    if entry.get("event_id") != expected_id:
        raise SchemaValidationError("event_id does not match canonical hash surface (fail-closed)")

