from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64
from schemas.fl3_schema_common import ensure_sorted_str_list, sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_FACTORY_PROMOTION_SCHEMA_ID = "kt.factory.promotion.v1"
FL3_FACTORY_PROMOTION_SCHEMA_FILE = "fl3/kt.factory.promotion.v1.json"
FL3_FACTORY_PROMOTION_SCHEMA_VERSION_HASH = schema_version_hash(FL3_FACTORY_PROMOTION_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "promotion_id",
    "job_id",
    "decision",
    "reasons",
    "links",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "promotion_id"}


def validate_fl3_factory_promotion(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 factory promotion")
    enforce_max_fields(entry, max_fields=24)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_FACTORY_PROMOTION_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_FACTORY_PROMOTION_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "promotion_id")
    validate_hex_64(entry, "job_id")
    validate_created_at_utc_z(entry.get("created_at"))

    if entry.get("decision") not in {"PROMOTE", "QUARANTINE", "REJECT"}:
        raise SchemaValidationError("decision invalid (fail-closed)")

    reasons = entry.get("reasons")
    _ = ensure_sorted_str_list(reasons, field="reasons")
    for r in reasons:
        if len(r) != 64 or any(c not in "0123456789abcdef" for c in r):
            raise SchemaValidationError("reasons must be 64 lowercase hex hashes (fail-closed)")

    links = entry.get("links")
    if not isinstance(links, dict):
        raise SchemaValidationError("links must be an object (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("promotion_id") != expected:
        raise SchemaValidationError("promotion_id does not match canonical hash surface (fail-closed)")

