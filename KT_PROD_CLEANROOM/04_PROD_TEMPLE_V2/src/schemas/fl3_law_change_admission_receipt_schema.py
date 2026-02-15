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
from schemas.fl3_schema_common import ensure_sorted_str_list, sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_LAW_CHANGE_ADMISSION_RECEIPT_SCHEMA_ID = "kt.law_change_admission_receipt.v1"
FL3_LAW_CHANGE_ADMISSION_RECEIPT_SCHEMA_FILE = "fl3/kt.law_change_admission_receipt.v1.json"
FL3_LAW_CHANGE_ADMISSION_RECEIPT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_LAW_CHANGE_ADMISSION_RECEIPT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "law_change_admission_receipt_id",
    "decision",
    "reason_codes",
    "current_bundle_hash",
    "requested_bundle_hash",
    "law_bundle_change_receipt_ref",
    "law_bundle_change_receipt_sha256",
    "cooldown_seconds",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {"notes"}
_HASH_DROP_KEYS = {"created_at", "law_change_admission_receipt_id"}


def validate_fl3_law_change_admission_receipt(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 law change admission receipt v1")
    enforce_max_fields(entry, max_fields=64)
    enforce_max_canonical_json_bytes(entry, max_bytes=96_000)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_LAW_CHANGE_ADMISSION_RECEIPT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_LAW_CHANGE_ADMISSION_RECEIPT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "law_change_admission_receipt_id")
    validate_created_at_utc_z(entry.get("created_at"))

    decision = str(entry.get("decision", "")).strip().upper()
    if decision not in {"PASS", "FAIL_CLOSED"}:
        raise SchemaValidationError("decision invalid (fail-closed)")
    entry["decision"] = decision

    entry["reason_codes"] = ensure_sorted_str_list(entry.get("reason_codes"), field="reason_codes")
    validate_hex_64(entry, "current_bundle_hash")
    validate_hex_64(entry, "requested_bundle_hash")
    validate_short_string(entry, "law_bundle_change_receipt_ref", max_len=512)
    validate_hex_64(entry, "law_bundle_change_receipt_sha256")

    cs = entry.get("cooldown_seconds")
    if not isinstance(cs, int) or cs < 0:
        raise SchemaValidationError("cooldown_seconds must be an integer >=0 (fail-closed)")
    entry["cooldown_seconds"] = int(cs)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("law_change_admission_receipt_id") != expected:
        raise SchemaValidationError("law_change_admission_receipt_id does not match canonical hash surface (fail-closed)")

