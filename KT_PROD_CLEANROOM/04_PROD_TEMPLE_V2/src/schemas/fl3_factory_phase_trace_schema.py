from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64, validate_short_string
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_FACTORY_PHASE_TRACE_SCHEMA_ID = "kt.factory.phase_trace.v1"
FL3_FACTORY_PHASE_TRACE_SCHEMA_FILE = "fl3/kt.factory.phase_trace.v1.json"
FL3_FACTORY_PHASE_TRACE_SCHEMA_VERSION_HASH = schema_version_hash(FL3_FACTORY_PHASE_TRACE_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "phase_trace_id",
    "job_id",
    "phases",
    "no_stub_executed",
    "parent_hash",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "phase_trace_id"}


def validate_fl3_factory_phase_trace(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL4 phase trace")
    enforce_max_fields(entry, max_fields=64)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_FACTORY_PHASE_TRACE_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_FACTORY_PHASE_TRACE_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "phase_trace_id")
    validate_hex_64(entry, "job_id")
    validate_hex_64(entry, "parent_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    if not isinstance(entry.get("no_stub_executed"), bool):
        raise SchemaValidationError("no_stub_executed must be boolean (fail-closed)")

    phases = entry.get("phases")
    if not isinstance(phases, list) or len(phases) < 1:
        raise SchemaValidationError("phases must be non-empty list (fail-closed)")
    for item in phases:
        p = require_dict(item, name="phase trace entry")
        if set(p.keys()) != {"phase", "module_path", "status"}:
            raise SchemaValidationError("phase entry keys mismatch (fail-closed)")
        validate_short_string(p, "phase", max_len=64)
        validate_short_string(p, "module_path", max_len=256)
        if p.get("status") not in {"OK", "SKIPPED", "FAIL"}:
            raise SchemaValidationError("phase entry status invalid (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("phase_trace_id") != expected:
        raise SchemaValidationError("phase_trace_id does not match canonical hash surface (fail-closed)")

