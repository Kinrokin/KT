from __future__ import annotations

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
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_META_EVALUATOR_RECEIPT_SCHEMA_ID = "kt.meta_evaluator_receipt.v1"
FL3_META_EVALUATOR_RECEIPT_SCHEMA_FILE = "fl3/kt.meta_evaluator_receipt.v1.json"
FL3_META_EVALUATOR_RECEIPT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_META_EVALUATOR_RECEIPT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "receipt_id",
    "law_bundle_hash",
    "active_law_id",
    "active_law_hash",
    "status",
    "parent_hash",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "receipt_id"}


def validate_fl3_meta_evaluator_receipt(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 meta evaluator receipt")
    enforce_max_fields(entry, max_fields=32)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_META_EVALUATOR_RECEIPT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_META_EVALUATOR_RECEIPT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")
    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "receipt_id")
    validate_hex_64(entry, "law_bundle_hash")
    validate_hex_64(entry, "active_law_hash")
    validate_hex_64(entry, "parent_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    validate_short_string(entry, "active_law_id", max_len=128)
    if entry.get("status") not in {"PASS", "FAIL"}:
        raise SchemaValidationError("status must be PASS or FAIL (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("receipt_id") != expected:
        raise SchemaValidationError("receipt_id does not match canonical hash surface (fail-closed)")

