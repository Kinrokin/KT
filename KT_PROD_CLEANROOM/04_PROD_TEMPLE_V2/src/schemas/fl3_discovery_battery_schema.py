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
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_DISCOVERY_BATTERY_SCHEMA_ID = "kt.discovery_battery.v1"
FL3_DISCOVERY_BATTERY_SCHEMA_FILE = "fl3/kt.discovery_battery.v1.json"
FL3_DISCOVERY_BATTERY_SCHEMA_VERSION_HASH = schema_version_hash(FL3_DISCOVERY_BATTERY_SCHEMA_FILE)

_REQUIRED_ORDER = ("schema_id", "schema_version_hash", "battery_id", "cases", "created_at")
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "battery_id"}

_CATEGORIES = {
    "paradox_pressure",
    "cross_domain_transfer",
    "multi_step_reasoning",
    "self_repair",
    "novel_composition",
    "governance_canary",
}


def validate_fl3_discovery_battery(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 discovery battery")
    enforce_max_fields(entry, max_fields=16)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_DISCOVERY_BATTERY_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_DISCOVERY_BATTERY_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "battery_id")
    validate_created_at_utc_z(entry.get("created_at"))

    cases = entry.get("cases")
    if not isinstance(cases, list) or len(cases) < 1:
        raise SchemaValidationError("cases must be non-empty list (fail-closed)")
    for c in cases:
        cd = require_dict(c, name="discovery case")
        enforce_max_fields(cd, max_fields=16)
        require_keys(cd, required={"case_id", "category", "prompt", "is_canary"})
        reject_unknown_keys(cd, allowed={"case_id", "category", "prompt", "is_canary"})
        if not isinstance(cd.get("case_id"), str) or not str(cd.get("case_id")).strip():
            raise SchemaValidationError("case_id must be non-empty string (fail-closed)")
        cat = cd.get("category")
        if not isinstance(cat, str) or cat not in _CATEGORIES:
            raise SchemaValidationError("category invalid (fail-closed)")
        if not isinstance(cd.get("prompt"), str):
            raise SchemaValidationError("prompt must be string (fail-closed)")
        if not isinstance(cd.get("is_canary"), bool):
            raise SchemaValidationError("is_canary must be bool (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("battery_id") != expected:
        raise SchemaValidationError("battery_id mismatch vs canonical hash surface (fail-closed)")

