from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64, validate_short_string
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_FACTORY_FREEZE_RECEIPT_SCHEMA_ID = "kt.factory.freeze_receipt.v1"
FL3_FACTORY_FREEZE_RECEIPT_SCHEMA_FILE = "fl3/kt.factory.freeze_receipt.v1.json"
FL3_FACTORY_FREEZE_RECEIPT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_FACTORY_FREEZE_RECEIPT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "freeze_id",
    "job_id",
    "adapter_id",
    "adapter_version",
    "bundle_hash",
    "eval_hash",
    "promotion_hash",
    "registry_write",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "freeze_id"}


def validate_fl3_factory_freeze_receipt(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 factory freeze receipt")
    enforce_max_fields(entry, max_fields=24)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_FACTORY_FREEZE_RECEIPT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_FACTORY_FREEZE_RECEIPT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "freeze_id")
    validate_hex_64(entry, "job_id")
    validate_short_string(entry, "adapter_id", max_len=128)
    validate_short_string(entry, "adapter_version", max_len=64)
    validate_hex_64(entry, "bundle_hash")
    validate_hex_64(entry, "eval_hash")
    validate_hex_64(entry, "promotion_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    rw = entry.get("registry_write")
    if rw is not None and not isinstance(rw, dict):
        raise SchemaValidationError("registry_write must be object or null (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("freeze_id") != expected:
        raise SchemaValidationError("freeze_id does not match canonical hash surface (fail-closed)")

