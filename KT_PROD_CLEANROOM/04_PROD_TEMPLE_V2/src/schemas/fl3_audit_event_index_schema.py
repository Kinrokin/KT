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


FL3_AUDIT_EVENT_INDEX_SCHEMA_ID = "kt.audit_event_index.v1"
FL3_AUDIT_EVENT_INDEX_SCHEMA_FILE = "fl3/kt.audit_event_index.v1.json"
FL3_AUDIT_EVENT_INDEX_SCHEMA_VERSION_HASH = schema_version_hash(FL3_AUDIT_EVENT_INDEX_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "index_id",
    "vault_root_rel",
    "entries",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)


def _validate_entry(obj: Any) -> str:
    entry = require_dict(obj, name="audit_event_index.entries[]")
    require_keys(entry, required={"path", "sha256", "event_id"})
    reject_unknown_keys(entry, allowed={"path", "sha256", "event_id"})
    validate_short_string(entry, "path", max_len=2048)
    p = str(entry.get("path", "")).strip()
    if p.startswith("/") or ".." in p.split("/"):
        raise SchemaValidationError("entries[].path must be clean relative path (fail-closed)")
    validate_hex_64(entry, "sha256")
    validate_hex_64(entry, "event_id")
    return p


def validate_fl3_audit_event_index(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 audit event index")
    enforce_max_fields(entry, max_fields=32)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    enforce_max_canonical_json_bytes(entry, max_bytes=512 * 1024)

    if entry.get("schema_id") != FL3_AUDIT_EVENT_INDEX_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_AUDIT_EVENT_INDEX_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "index_id")
    validate_short_string(entry, "vault_root_rel", max_len=1024)
    validate_created_at_utc_z(entry.get("created_at"))

    entries = entry.get("entries")
    if not isinstance(entries, list):
        raise SchemaValidationError("entries must be a list (fail-closed)")
    prev = None
    for it in entries:
        p = _validate_entry(it)
        if prev is not None and p < prev:
            raise SchemaValidationError("entries must be sorted by path (fail-closed)")
        prev = p

    expected_id = sha256_hex_of_obj(entry, drop_keys={"created_at", "index_id"})
    if entry.get("index_id") != expected_id:
        raise SchemaValidationError("index_id does not match canonical hash surface (fail-closed)")

