from __future__ import annotations

from typing import Any, Dict, List, Set

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
from schemas.fl3_schema_common import validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_CHANGE_RECEIPT_SCHEMA_ID = "kt.change_receipt.v1"
FL3_CHANGE_RECEIPT_SCHEMA_FILE = "fl3/kt.change_receipt.v1.json"
FL3_CHANGE_RECEIPT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_CHANGE_RECEIPT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "change_id",
    "actor",
    "phase",
    "phase_id",
    "timestamp_utc",
    "files_checked",
    "outcome",
    "notes",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)

_FILE_REQUIRED = {"path", "sha256"}
_FILE_ALLOWED = set(_FILE_REQUIRED)


def _validate_files_checked(rows_val: Any) -> List[Dict[str, Any]]:
    if not isinstance(rows_val, list) or not rows_val:
        raise SchemaValidationError("files_checked must be non-empty list (fail-closed)")
    rows: List[Dict[str, Any]] = []
    for item in rows_val:
        row = require_dict(item, name="files_checked[]")
        enforce_max_fields(row, max_fields=8)
        require_keys(row, required=_FILE_REQUIRED)
        reject_unknown_keys(row, allowed=_FILE_ALLOWED)
        validate_bounded_json_value(row, max_depth=3, max_string_len=512, max_list_len=32)
        path = str(row.get("path", "")).strip()
        if not path:
            raise SchemaValidationError("files_checked[].path must be non-empty (fail-closed)")
        validate_short_string({"path": path}, "path", max_len=512)
        row["path"] = path
        validate_hex_64(row, "sha256")
        rows.append(row)
    return rows


def validate_fl3_change_receipt(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="change_receipt")
    enforce_max_fields(entry, max_fields=64)
    enforce_max_canonical_json_bytes(entry, max_bytes=256_000)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_CHANGE_RECEIPT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_CHANGE_RECEIPT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "change_id")

    actor = str(entry.get("actor", "")).strip()
    if not actor:
        raise SchemaValidationError("actor must be non-empty (fail-closed)")
    validate_short_string({"actor": actor}, "actor", max_len=128)
    entry["actor"] = actor

    phase = str(entry.get("phase", "")).strip()
    if phase not in {"pre", "post"}:
        raise SchemaValidationError("phase must be 'pre' or 'post' (fail-closed)")
    entry["phase"] = phase

    phase_id = str(entry.get("phase_id", "")).strip()
    if not phase_id:
        raise SchemaValidationError("phase_id must be non-empty (fail-closed)")
    validate_short_string({"phase_id": phase_id}, "phase_id", max_len=128)
    entry["phase_id"] = phase_id

    validate_created_at_utc_z(entry.get("timestamp_utc"))

    outcome = str(entry.get("outcome", "")).strip()
    if outcome not in {"PASS", "FAIL"}:
        raise SchemaValidationError("outcome must be PASS|FAIL (fail-closed)")
    entry["outcome"] = outcome

    notes = str(entry.get("notes", ""))
    validate_short_string({"notes": notes}, "notes", max_len=32_000)
    entry["notes"] = notes

    entry["files_checked"] = _validate_files_checked(entry.get("files_checked"))

