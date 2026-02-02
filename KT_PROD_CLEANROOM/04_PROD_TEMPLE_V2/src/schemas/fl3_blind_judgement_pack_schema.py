from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_BLIND_JUDGEMENT_PACK_SCHEMA_ID = "kt.blind_judgement_pack.v1"
FL3_BLIND_JUDGEMENT_PACK_SCHEMA_FILE = "fl3/kt.blind_judgement_pack.v1.json"
FL3_BLIND_JUDGEMENT_PACK_SCHEMA_VERSION_HASH = schema_version_hash(FL3_BLIND_JUDGEMENT_PACK_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "pack_id",
    "job_id",
    "items",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "pack_id"}


def validate_fl3_blind_judgement_pack(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 blind judgement pack")
    enforce_max_fields(entry, max_fields=16)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_BLIND_JUDGEMENT_PACK_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_BLIND_JUDGEMENT_PACK_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "pack_id")
    validate_hex_64(entry, "job_id")
    validate_created_at_utc_z(entry.get("created_at"))

    items = entry.get("items")
    if not isinstance(items, list) or not items:
        raise SchemaValidationError("items must be a non-empty list (fail-closed)")
    for it in items:
        item = require_dict(it, name="Blind pack item")
        if set(item.keys()) != {"prompt_hash", "candidate_hash"}:
            raise SchemaValidationError("blind pack item keys must be exactly prompt_hash,candidate_hash (fail-closed)")
        validate_hex_64(item, "prompt_hash")
        validate_hex_64(item, "candidate_hash")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("pack_id") != expected:
        raise SchemaValidationError("pack_id does not match canonical hash surface (fail-closed)")

