from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64, validate_short_string
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_TOURNAMENT_MANIFEST_SCHEMA_ID = "kt.tournament_manifest.v1"
FL3_TOURNAMENT_MANIFEST_SCHEMA_FILE = "fl3/kt.tournament_manifest.v1.json"
FL3_TOURNAMENT_MANIFEST_SCHEMA_VERSION_HASH = schema_version_hash(FL3_TOURNAMENT_MANIFEST_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "tournament_id",
    "job_id",
    "blind_pack_ref",
    "reveal_mapping_ref",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "tournament_id"}


def validate_fl3_tournament_manifest(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 tournament manifest")
    enforce_max_fields(entry, max_fields=24)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_TOURNAMENT_MANIFEST_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_TOURNAMENT_MANIFEST_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "tournament_id")
    validate_hex_64(entry, "job_id")
    validate_created_at_utc_z(entry.get("created_at"))
    validate_short_string(entry, "blind_pack_ref", max_len=256)
    validate_short_string(entry, "reveal_mapping_ref", max_len=256)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("tournament_id") != expected:
        raise SchemaValidationError("tournament_id does not match canonical hash surface (fail-closed)")

