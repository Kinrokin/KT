from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_canonical_json_bytes,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_hex_64,
    validate_short_string,
)
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_DETERMINISM_ANCHOR_SCHEMA_ID = "kt.determinism_anchor.v1"
FL3_DETERMINISM_ANCHOR_SCHEMA_FILE = "fl3/kt.determinism_anchor.v1.json"
FL3_DETERMINISM_ANCHOR_SCHEMA_VERSION_HASH = schema_version_hash(FL3_DETERMINISM_ANCHOR_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "anchor_id",
    "determinism_contract_law_hash",
    "expected_determinism_root_hash",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {"notes"}
_HASH_DROP_KEYS = {"created_at", "anchor_id"}


def validate_fl3_determinism_anchor(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="determinism_anchor")
    enforce_max_fields(entry, max_fields=32)
    enforce_max_canonical_json_bytes(entry, max_bytes=64 * 1024)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_DETERMINISM_ANCHOR_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_DETERMINISM_ANCHOR_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "anchor_id")
    validate_hex_64(entry, "determinism_contract_law_hash")
    validate_hex_64(entry, "expected_determinism_root_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    notes = entry.get("notes")
    if notes is not None:
        validate_short_string({"notes": str(notes)}, "notes", max_len=16_000)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("anchor_id") != expected:
        raise SchemaValidationError("anchor_id does not match canonical hash surface (fail-closed)")
