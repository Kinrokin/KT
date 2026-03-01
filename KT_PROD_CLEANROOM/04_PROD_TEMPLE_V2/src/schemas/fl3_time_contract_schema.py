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


FL3_TIME_CONTRACT_SCHEMA_ID = "kt.time_contract.v1"
FL3_TIME_CONTRACT_SCHEMA_FILE = "fl3/kt.time_contract.v1.json"
FL3_TIME_CONTRACT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_TIME_CONTRACT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "time_contract_id",
    "timestamp_policy",
    "hash_surface_policy",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {"notes"}
_HASH_DROP_KEYS = {"created_at", "time_contract_id"}


def validate_fl3_time_contract(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="time_contract")
    enforce_max_fields(entry, max_fields=64)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_TIME_CONTRACT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_TIME_CONTRACT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "time_contract_id")
    validate_created_at_utc_z(entry.get("created_at"))

    tp = require_dict(entry.get("timestamp_policy"), name="timestamp_policy")
    for k in ("run_evidence_clock", "derived_artifacts_clock", "fallback_clock"):
        if not isinstance(tp.get(k), str) or not str(tp.get(k)).strip():
            raise SchemaValidationError(f"timestamp_policy.{k} must be non-empty string (fail-closed)")

    hsp = require_dict(entry.get("hash_surface_policy"), name="hash_surface_policy")
    must_drop = hsp.get("must_drop_keys")
    if not isinstance(must_drop, list) or not all(isinstance(x, str) and x.strip() for x in must_drop):
        raise SchemaValidationError("hash_surface_policy.must_drop_keys must be list of strings (fail-closed)")
    if "created_at" not in set(must_drop):
        raise SchemaValidationError("hash_surface_policy.must_drop_keys must include created_at (fail-closed)")
    if not isinstance(hsp.get("must_not_include_wall_clock_in_hashes"), bool):
        raise SchemaValidationError("hash_surface_policy.must_not_include_wall_clock_in_hashes must be bool (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("time_contract_id") != expected:
        raise SchemaValidationError("time_contract_id does not match canonical hash surface (fail-closed)")

