from __future__ import annotations

import hashlib
import json
import re
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


ADAPTER_INVOCATION_SCHEMA_ID = "kt.adapter_invocation.v1"
ADAPTER_INVOCATION_SCHEMA_FILE = "kt.routing.air.v1.json"
ADAPTER_INVOCATION_SCHEMA_VERSION_HASH = schema_version_hash(ADAPTER_INVOCATION_SCHEMA_FILE)

ADAPTER_INVOCATION_REQUIRED_FIELDS_ORDER = (
    "schema_id",
    "schema_version_hash",
    "invocation_id",
    "routing_record_hash",
    "adapter_id",
    "adapter_version",
    "task_context_hash",
    "input_hash",
    "output_hash",
    "governor_verdict_hash",
    "evaluator_verdict",
    "duration_ms",
    "token_usage",
    "status",
    "created_at",
)

ADAPTER_INVOCATION_REQUIRED_FIELDS: Set[str] = set(ADAPTER_INVOCATION_REQUIRED_FIELDS_ORDER)
ADAPTER_INVOCATION_ALLOWED_FIELDS: Set[str] = set(ADAPTER_INVOCATION_REQUIRED_FIELDS_ORDER)

_UTC_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")

_HASH_DROP_KEYS = {"created_at", "invocation_id"}


def _canonical_json(obj: Dict[str, Any]) -> str:
    # Deterministic hash surface: strict key sorting, stable separators, ASCII-only output.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _compute_invocation_id(record: Dict[str, Any]) -> str:
    payload = {k: v for k, v in record.items() if k not in _HASH_DROP_KEYS}
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def validate_adapter_invocation(record: Dict[str, Any]) -> None:
    require_dict(record, name="Adapter invocation")
    enforce_max_fields(record, max_fields=32)
    require_keys(record, required=ADAPTER_INVOCATION_REQUIRED_FIELDS)
    reject_unknown_keys(record, allowed=ADAPTER_INVOCATION_ALLOWED_FIELDS)

    validate_short_string(record, "schema_id", max_len=64)
    validate_hex_64(record, "schema_version_hash")
    validate_hex_64(record, "invocation_id")
    validate_hex_64(record, "routing_record_hash")
    validate_hex_64(record, "task_context_hash")
    validate_hex_64(record, "input_hash")

    if record["schema_id"] != ADAPTER_INVOCATION_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if record["schema_version_hash"] != ADAPTER_INVOCATION_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_short_string(record, "adapter_id", max_len=128)
    validate_short_string(record, "adapter_version", max_len=64)

    output_hash = record.get("output_hash")
    if output_hash is not None:
        validate_hex_64(record, "output_hash")

    verdict_hash = record.get("governor_verdict_hash")
    if verdict_hash is not None:
        validate_hex_64(record, "governor_verdict_hash")

    if record.get("evaluator_verdict") not in {"PASS", "FAIL", "SKIPPED"}:
        raise SchemaValidationError("evaluator_verdict must be PASS, FAIL, or SKIPPED")

    duration = record.get("duration_ms")
    if not isinstance(duration, int) or duration < 0:
        raise SchemaValidationError("duration_ms must be a non-negative integer")

    status = record.get("status")
    if status not in {"OK", "FAILED", "VETOED", "DRY_RUN"}:
        raise SchemaValidationError("status must be OK, FAILED, VETOED, or DRY_RUN")

    created_at = record.get("created_at")
    if not isinstance(created_at, str) or not _UTC_Z_RE.match(created_at):
        raise SchemaValidationError("created_at must be UTC ISO-8601 with Z suffix")

    _validate_token_usage(record.get("token_usage"))

    # Non-deniable integrity: invocation_id must match canonical hash surface.
    expected = _compute_invocation_id(record)
    if record.get("invocation_id") != expected:
        raise SchemaValidationError("invocation_id does not match canonical hash surface (fail-closed)")


def _validate_token_usage(value: Any) -> None:
    entry = require_dict(value, name="token_usage")
    required = {"prompt", "completion", "total"}
    require_keys(entry, required=required)
    reject_unknown_keys(entry, allowed=required)
    for key in required:
        val = entry.get(key)
        if not isinstance(val, int) or val < 0:
            raise SchemaValidationError(f"token_usage.{key} must be a non-negative integer")
