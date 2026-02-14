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


FL3_GOVERNANCE_TWIN_MANIFEST_SCHEMA_ID = "kt.governance_twin_manifest.v1"
FL3_GOVERNANCE_TWIN_MANIFEST_SCHEMA_FILE = "fl3/kt.governance_twin_manifest.v1.json"
FL3_GOVERNANCE_TWIN_MANIFEST_SCHEMA_VERSION_HASH = schema_version_hash(FL3_GOVERNANCE_TWIN_MANIFEST_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "twin_manifest_id",
    "run_id",
    "lane_id",
    "law_bundle_hash",
    "time_contract_id",
    "run_protocol_id",
    "run_protocol_json_hash",
    "bundle_root_hash",
    "created_at",
)
_OPTIONAL_ORDER = ("notes",)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)
_HASH_DROP_KEYS = {"created_at", "twin_manifest_id"}


def validate_fl3_governance_twin_manifest(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="governance_twin_manifest")
    enforce_max_fields(entry, max_fields=64)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_GOVERNANCE_TWIN_MANIFEST_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_GOVERNANCE_TWIN_MANIFEST_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "twin_manifest_id")
    validate_hex_64(entry, "law_bundle_hash")
    validate_hex_64(entry, "time_contract_id")
    validate_hex_64(entry, "run_protocol_id")
    validate_hex_64(entry, "run_protocol_json_hash")
    validate_hex_64(entry, "bundle_root_hash")

    validate_short_string(entry, "run_id", max_len=128)
    validate_short_string(entry, "lane_id", max_len=64)
    validate_created_at_utc_z(entry.get("created_at"))
    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("twin_manifest_id") != expected:
        raise SchemaValidationError("twin_manifest_id does not match canonical hash surface (fail-closed)")

