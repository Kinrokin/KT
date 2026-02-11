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
    validate_hex_64,
)
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_REASONING_TRACE_SCHEMA_ID = "kt.reasoning_trace.v1"
FL3_REASONING_TRACE_SCHEMA_FILE = "fl3/kt.reasoning_trace.v1.json"
FL3_REASONING_TRACE_SCHEMA_VERSION_HASH = schema_version_hash(FL3_REASONING_TRACE_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "trace_id",
    "steps",
    "final_output_hash",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "trace_id"}


def validate_fl3_reasoning_trace(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 reasoning trace")
    enforce_max_fields(entry, max_fields=16)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    enforce_max_canonical_json_bytes(entry, max_bytes=256 * 1024)

    if entry.get("schema_id") != FL3_REASONING_TRACE_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_REASONING_TRACE_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "trace_id")
    validate_hex_64(entry, "final_output_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    steps = entry.get("steps")
    if not isinstance(steps, list) or not steps:
        raise SchemaValidationError("steps must be a non-empty list (fail-closed)")
    validate_bounded_json_value(steps, max_depth=10, max_string_len=4096, max_list_len=4096)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("trace_id") != expected:
        raise SchemaValidationError("trace_id does not match canonical hash surface (fail-closed)")

