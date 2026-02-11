from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_hex_64,
)
from schemas.fl3_schema_common import ensure_sorted_str_list, sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_ENV_LOCK_SCHEMA_ID = "kt.env_lock.v1"
FL3_ENV_LOCK_SCHEMA_FILE = "fl3/kt.env_lock.v1.json"
FL3_ENV_LOCK_SCHEMA_VERSION_HASH = schema_version_hash(FL3_ENV_LOCK_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "env_lock_id",
    "required",
    "forbidden",
    "forbidden_prefixes",
    "allow_extra",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "env_lock_id"}


def validate_fl3_env_lock(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="env_lock")
    enforce_max_fields(entry, max_fields=64)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_ENV_LOCK_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_ENV_LOCK_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "env_lock_id")
    validate_created_at_utc_z(entry.get("created_at"))

    required = entry.get("required")
    forbidden = entry.get("forbidden")
    forbidden_prefixes = entry.get("forbidden_prefixes")
    allow_extra = entry.get("allow_extra")

    if not isinstance(required, dict) or not required:
        raise SchemaValidationError("required must be non-empty object (fail-closed)")
    if not isinstance(forbidden, dict):
        raise SchemaValidationError("forbidden must be object (fail-closed)")
    forbidden_prefixes_list = ensure_sorted_str_list(forbidden_prefixes, field="forbidden_prefixes")
    allow_extra_list = ensure_sorted_str_list(allow_extra, field="allow_extra")

    for k, v in required.items():
        if not isinstance(k, str) or not k:
            raise SchemaValidationError("required keys must be non-empty strings (fail-closed)")
        if not isinstance(v, str):
            raise SchemaValidationError("required values must be strings (fail-closed)")

    for k, v in forbidden.items():
        if not isinstance(k, str) or not k:
            raise SchemaValidationError("forbidden keys must be non-empty strings (fail-closed)")
        if not isinstance(v, str):
            raise SchemaValidationError("forbidden values must be strings (fail-closed)")

    if len(set(forbidden_prefixes_list)) != len(forbidden_prefixes_list):
        raise SchemaValidationError("forbidden_prefixes must not contain duplicates (fail-closed)")
    if len(set(allow_extra_list)) != len(allow_extra_list):
        raise SchemaValidationError("allow_extra must not contain duplicates (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("env_lock_id") != expected:
        raise SchemaValidationError("env_lock_id does not match canonical hash surface (fail-closed)")
