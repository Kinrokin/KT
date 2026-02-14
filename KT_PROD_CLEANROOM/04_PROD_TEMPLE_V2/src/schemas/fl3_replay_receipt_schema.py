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


FL3_REPLAY_RECEIPT_SCHEMA_ID = "kt.replay_receipt.v1"
FL3_REPLAY_RECEIPT_SCHEMA_FILE = "fl3/kt.replay_receipt.v1.json"
FL3_REPLAY_RECEIPT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_REPLAY_RECEIPT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "replay_receipt_id",
    "run_id",
    "lane_id",
    "replay_command",
    "replay_sh_sha256",
    "replay_ps1_sha256",
    "replay_script_hash",
    "created_at",
)
_OPTIONAL_ORDER = ("notes",)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)


def validate_fl3_replay_receipt(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 replay receipt")
    enforce_max_fields(entry, max_fields=24)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    enforce_max_canonical_json_bytes(entry, max_bytes=64 * 1024)

    if entry.get("schema_id") != FL3_REPLAY_RECEIPT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_REPLAY_RECEIPT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "replay_receipt_id")
    validate_hex_64(entry, "replay_sh_sha256")
    validate_hex_64(entry, "replay_ps1_sha256")
    validate_hex_64(entry, "replay_script_hash")

    validate_short_string(entry, "run_id", max_len=128)
    validate_short_string(entry, "lane_id", max_len=64)
    validate_short_string(entry, "replay_command", max_len=4096)
    validate_created_at_utc_z(entry.get("created_at"))

    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    expected_id = sha256_hex_of_obj(entry, drop_keys={"created_at", "replay_receipt_id"})
    if entry.get("replay_receipt_id") != expected_id:
        raise SchemaValidationError("replay_receipt_id does not match canonical hash surface (fail-closed)")

