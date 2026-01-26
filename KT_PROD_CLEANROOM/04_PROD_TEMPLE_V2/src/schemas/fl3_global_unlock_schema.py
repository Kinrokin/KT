from __future__ import annotations

from typing import Any, Dict, List, Set

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_hex_64,
)
from schemas.fl3_human_signoff_schema import validate_fl3_human_signoff
from schemas.fl3_schema_common import ensure_sorted_str_list, sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_GLOBAL_UNLOCK_SCHEMA_ID = "kt.global_unlock.v1"
FL3_GLOBAL_UNLOCK_SCHEMA_FILE = "fl3/kt.global_unlock.v1.json"
FL3_GLOBAL_UNLOCK_SCHEMA_VERSION_HASH = schema_version_hash(FL3_GLOBAL_UNLOCK_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "unlock_id",
    "payload_hash",
    "reason_codes",
    "signoffs",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "unlock_id"}


def validate_fl3_global_unlock(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 global unlock")
    enforce_max_fields(entry, max_fields=32)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_GLOBAL_UNLOCK_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_GLOBAL_UNLOCK_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "unlock_id")
    validate_hex_64(entry, "payload_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    _ = ensure_sorted_str_list(entry.get("reason_codes"), field="reason_codes")
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
    if entry.get("unlock_id") != expected:
        raise SchemaValidationError("unlock_id does not match canonical hash surface (fail-closed)")

