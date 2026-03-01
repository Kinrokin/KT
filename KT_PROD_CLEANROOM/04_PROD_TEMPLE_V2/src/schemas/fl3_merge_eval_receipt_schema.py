from __future__ import annotations

from typing import Any, Dict, List, Set

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


FL3_MERGE_EVAL_RECEIPT_SCHEMA_ID = "kt.merge_eval_receipt.v1"
FL3_MERGE_EVAL_RECEIPT_SCHEMA_FILE = "fl3/kt.merge_eval_receipt.v1.json"
FL3_MERGE_EVAL_RECEIPT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_MERGE_EVAL_RECEIPT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "merge_eval_receipt_id",
    "merge_manifest_id",
    "status",
    "safety_regression",
    "utility_gate_pass",
    "tournament_result_ref",
    "created_at",
)
_OPTIONAL_ORDER = ("reason_codes", "notes")
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)
_HASH_DROP_KEYS = {"created_at", "merge_eval_receipt_id"}
_ALLOWED_STATUS = {"PASS", "FAIL_CLOSED"}


def _validate_reason_codes(value: Any, *, required: bool) -> List[str]:
    if value is None:
        if required:
            raise SchemaValidationError("reason_codes missing (fail-closed)")
        return []
    if not isinstance(value, list):
        raise SchemaValidationError("reason_codes must be list (fail-closed)")
    out: List[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise SchemaValidationError("reason_codes entries must be non-empty strings (fail-closed)")
        out.append(item.strip())
    if out != sorted(out):
        raise SchemaValidationError("reason_codes must be sorted (fail-closed)")
    if len(set(out)) != len(out):
        raise SchemaValidationError("reason_codes must be unique (fail-closed)")
    if required and not out:
        raise SchemaValidationError("FAIL_CLOSED requires non-empty reason_codes (fail-closed)")
    return out


def validate_fl3_merge_eval_receipt(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="merge_eval_receipt")
    enforce_max_fields(entry, max_fields=256)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_MERGE_EVAL_RECEIPT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_MERGE_EVAL_RECEIPT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "merge_eval_receipt_id")
    validate_hex_64(entry, "merge_manifest_id")
    validate_created_at_utc_z(entry.get("created_at"))

    status = str(entry.get("status", "")).strip().upper()
    if status not in _ALLOWED_STATUS:
        raise SchemaValidationError("status invalid (fail-closed)")
    _ = _validate_reason_codes(entry.get("reason_codes"), required=(status == "FAIL_CLOSED"))

    if not isinstance(entry.get("safety_regression"), bool):
        raise SchemaValidationError("safety_regression must be boolean (fail-closed)")
    if not isinstance(entry.get("utility_gate_pass"), bool):
        raise SchemaValidationError("utility_gate_pass must be boolean (fail-closed)")

    validate_short_string(entry, "tournament_result_ref", max_len=512)

    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("merge_eval_receipt_id") != expected:
        raise SchemaValidationError("merge_eval_receipt_id does not match canonical hash surface (fail-closed)")


