from __future__ import annotations

import hashlib
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


FL3_TRAINING_ADMISSION_RECEIPT_SCHEMA_ID = "kt.training_admission_receipt.v1"
FL3_TRAINING_ADMISSION_RECEIPT_SCHEMA_FILE = "fl3/kt.training_admission_receipt.v1.json"
FL3_TRAINING_ADMISSION_RECEIPT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_TRAINING_ADMISSION_RECEIPT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "admission_receipt_id",
    "lane_id",
    "decision",
    "reason_codes",
    "job_ref",
    "job_sha256",
    "law_bundle_hash",
    "failure_taxonomy_id",
    "created_at",
)
_OPTIONAL_ORDER = ("notes",)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)
_HASH_DROP_KEYS = {"created_at", "admission_receipt_id"}
_ALLOWED_DECISIONS = {"PASS", "FAIL_CLOSED"}


def _validate_reason_codes(value: Any) -> List[str]:
    if not isinstance(value, list):
        raise SchemaValidationError("reason_codes must be a list (fail-closed)")
    out: List[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise SchemaValidationError("reason_codes entries must be non-empty strings (fail-closed)")
        out.append(item.strip())
    if out != sorted(out):
        raise SchemaValidationError("reason_codes must be sorted (fail-closed)")
    if len(set(out)) != len(out):
        raise SchemaValidationError("reason_codes must be unique (fail-closed)")
    return out


def validate_fl3_training_admission_receipt(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="training_admission_receipt")
    enforce_max_fields(entry, max_fields=64)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_TRAINING_ADMISSION_RECEIPT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_TRAINING_ADMISSION_RECEIPT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "admission_receipt_id")
    validate_hex_64(entry, "job_sha256")
    validate_hex_64(entry, "law_bundle_hash")
    validate_hex_64(entry, "failure_taxonomy_id")
    validate_created_at_utc_z(entry.get("created_at"))

    validate_short_string(entry, "lane_id", max_len=64)
    validate_short_string(entry, "job_ref", max_len=512)
    decision = str(entry.get("decision", "")).strip().upper()
    if decision not in _ALLOWED_DECISIONS:
        raise SchemaValidationError("decision invalid (fail-closed)")

    reasons = _validate_reason_codes(entry.get("reason_codes"))
    if decision == "FAIL_CLOSED" and not reasons:
        raise SchemaValidationError("FAIL_CLOSED requires non-empty reason_codes (fail-closed)")

    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("admission_receipt_id") != expected:
        raise SchemaValidationError("admission_receipt_id does not match canonical hash surface (fail-closed)")


