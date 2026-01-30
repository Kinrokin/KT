from __future__ import annotations

from typing import Any, Dict, List, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64
from schemas.fl3_human_signoff_schema import validate_fl3_human_signoff
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_LAW_AMENDMENT_SCHEMA_ID = "kt.law_amendment.v1"
FL3_LAW_AMENDMENT_SCHEMA_FILE = "fl3/kt.law_amendment.v1.json"
FL3_LAW_AMENDMENT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_LAW_AMENDMENT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "amendment_id",
    "bundle_hash",
    "signoffs",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "amendment_id"}


def validate_fl3_law_amendment(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 law amendment")
    enforce_max_fields(entry, max_fields=24)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_LAW_AMENDMENT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_LAW_AMENDMENT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "amendment_id")
    validate_hex_64(entry, "bundle_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    signoffs = entry.get("signoffs")
    if not isinstance(signoffs, list) or len(signoffs) < 2:
        raise SchemaValidationError("signoffs must be a list with >=2 entries (fail-closed)")
    key_ids: List[str] = []
    for s in signoffs:
        sd = require_dict(s, name="Signoff")
        validate_fl3_human_signoff(sd)
        key_ids.append(str(sd.get("key_id", "")).strip())
    if len(set(key_ids)) < 2:
        raise SchemaValidationError("signoffs must include two distinct key_id values (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("amendment_id") != expected:
        raise SchemaValidationError("amendment_id does not match canonical hash surface (fail-closed)")

