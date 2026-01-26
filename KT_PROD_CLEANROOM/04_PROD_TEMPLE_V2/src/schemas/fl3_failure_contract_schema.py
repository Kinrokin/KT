from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64
from schemas.fl3_schema_common import validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_FAILURE_CONTRACT_SCHEMA_ID = "kt.failure_contract.v1"
FL3_FAILURE_CONTRACT_SCHEMA_FILE = "fl3/kt.failure_contract.v1.json"
FL3_FAILURE_CONTRACT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_FAILURE_CONTRACT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "tiers",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)

_REQUIRED_TIERS = ("T1", "T2", "T3", "T4")


def validate_fl3_failure_contract(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 failure contract")
    enforce_max_fields(entry, max_fields=16)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_FAILURE_CONTRACT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_FAILURE_CONTRACT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    tiers = entry.get("tiers")
    if not isinstance(tiers, dict):
        raise SchemaValidationError("tiers must be an object (fail-closed)")
    if set(tiers.keys()) != set(_REQUIRED_TIERS):
        raise SchemaValidationError("tiers must contain exactly T1,T2,T3,T4 (fail-closed)")
    for k in _REQUIRED_TIERS:
        t = require_dict(tiers.get(k), name=f"Tier {k}")
        # Minimum enforcement: each tier defines an auto_action and event_type.
        if set(t.keys()) != {"auto_action", "event_type"}:
            raise SchemaValidationError("each tier must contain exactly auto_action,event_type (fail-closed)")
        if not isinstance(t.get("auto_action"), str) or not t["auto_action"].strip():
            raise SchemaValidationError("auto_action must be non-empty string (fail-closed)")
        if not isinstance(t.get("event_type"), str) or not t["event_type"].strip():
            raise SchemaValidationError("event_type must be non-empty string (fail-closed)")

