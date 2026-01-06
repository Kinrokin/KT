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
    validate_short_string,
)
from schemas.schema_hash import sha256_json


RUNTIME_CONTEXT_SCHEMA_ID = "kt.runtime_context.v1"

RUNTIME_CONTEXT_REQUIRED_FIELDS_ORDER = (
    "envelope",
    "schema_id",
    "schema_version_hash",
    "constitution_version_hash",
)

RUNTIME_CONTEXT_REQUIRED_FIELDS: Set[str] = set(RUNTIME_CONTEXT_REQUIRED_FIELDS_ORDER)
RUNTIME_CONTEXT_ALLOWED_FIELDS: Set[str] = set(RUNTIME_CONTEXT_REQUIRED_FIELDS_ORDER)
RUNTIME_CONTEXT_ALLOWED_FIELDS.add("artifact_root")

RUNTIME_ENVELOPE_REQUIRED_FIELDS_ORDER = ("input",)
RUNTIME_ENVELOPE_REQUIRED_FIELDS: Set[str] = set(RUNTIME_ENVELOPE_REQUIRED_FIELDS_ORDER)
RUNTIME_ENVELOPE_ALLOWED_FIELDS: Set[str] = set(RUNTIME_ENVELOPE_REQUIRED_FIELDS_ORDER)

RUNTIME_CONTEXT_MAX_FIELDS = 8
RUNTIME_CONTEXT_MAX_DEPTH = 6
RUNTIME_CONTEXT_MAX_STRING_LEN = 256
RUNTIME_CONTEXT_MAX_LIST_LEN = 64

RUNTIME_CONTEXT_MAX_INPUT_BYTES = 64 * 1024
RUNTIME_CONTEXT_MAX_CONTEXT_BYTES = 128 * 1024


def compute_runtime_context_schema_version_hash() -> str:
    spec = {
        "schema_id": RUNTIME_CONTEXT_SCHEMA_ID,
        "required_fields": list(RUNTIME_CONTEXT_REQUIRED_FIELDS_ORDER),
        "envelope": {"required_fields": list(RUNTIME_ENVELOPE_REQUIRED_FIELDS_ORDER)},
        "limits": {
            "max_fields": RUNTIME_CONTEXT_MAX_FIELDS,
            "max_depth": RUNTIME_CONTEXT_MAX_DEPTH,
            "max_string_len": RUNTIME_CONTEXT_MAX_STRING_LEN,
            "max_list_len": RUNTIME_CONTEXT_MAX_LIST_LEN,
            "max_input_bytes": RUNTIME_CONTEXT_MAX_INPUT_BYTES,
            "max_context_bytes": RUNTIME_CONTEXT_MAX_CONTEXT_BYTES,
        },
    }
    return sha256_json(spec)


RUNTIME_CONTEXT_SCHEMA_VERSION_HASH = compute_runtime_context_schema_version_hash()


def validate_runtime_context(context: Dict[str, Any]) -> None:
    require_dict(context, name="Runtime context")
    enforce_max_fields(context, max_fields=RUNTIME_CONTEXT_MAX_FIELDS)

    require_keys(context, required=RUNTIME_CONTEXT_REQUIRED_FIELDS)
    reject_unknown_keys(context, allowed=RUNTIME_CONTEXT_ALLOWED_FIELDS)

    # artifact_root: optional, string, absolute path, max length 4096
    if "artifact_root" in context:
        value = context["artifact_root"]
        if not isinstance(value, str):
            raise SchemaValidationError("artifact_root must be a string (fail-closed)")
        if not value:
            raise SchemaValidationError("artifact_root must be non-empty (fail-closed)")
        if len(value) > 4096:
            raise SchemaValidationError("artifact_root too long (fail-closed)")
        from pathlib import Path
        if not Path(value).is_absolute():
            raise SchemaValidationError("artifact_root must be absolute path (fail-closed)")

    validate_short_string(context, "schema_id", max_len=64)
    validate_hex_64(context, "schema_version_hash")
    validate_hex_64(context, "constitution_version_hash")

    if context["schema_id"] != RUNTIME_CONTEXT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if context["schema_version_hash"] != RUNTIME_CONTEXT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    envelope = require_dict(context.get("envelope"), name="Runtime envelope")
    require_keys(envelope, required=RUNTIME_ENVELOPE_REQUIRED_FIELDS)
    reject_unknown_keys(envelope, allowed=RUNTIME_ENVELOPE_ALLOWED_FIELDS)

    if not isinstance(envelope.get("input"), str):
        raise SchemaValidationError("envelope.input must be a string")
    if len(envelope["input"].encode("utf-8")) > RUNTIME_CONTEXT_MAX_INPUT_BYTES:
        raise SchemaValidationError("envelope.input exceeds max_input_bytes (fail-closed)")

    validate_bounded_json_value(
        context,
        max_depth=RUNTIME_CONTEXT_MAX_DEPTH,
        max_string_len=RUNTIME_CONTEXT_MAX_STRING_LEN,
        max_list_len=RUNTIME_CONTEXT_MAX_LIST_LEN,
    )
    enforce_max_canonical_json_bytes(context, max_bytes=RUNTIME_CONTEXT_MAX_CONTEXT_BYTES)

