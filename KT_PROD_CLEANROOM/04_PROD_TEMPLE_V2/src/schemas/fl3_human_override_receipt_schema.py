from __future__ import annotations

from typing import Any, Dict, List, Set

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_hex_64,
    validate_short_string,
)
from schemas.fl3_human_signoff_v2_schema import validate_fl3_human_signoff_v2
from schemas.fl3_schema_common import ensure_sorted_str_list, sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_HUMAN_OVERRIDE_RECEIPT_SCHEMA_ID = "kt.human_override_receipt.v1"
FL3_HUMAN_OVERRIDE_RECEIPT_SCHEMA_FILE = "fl3/kt.human_override_receipt.v1.json"
FL3_HUMAN_OVERRIDE_RECEIPT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_HUMAN_OVERRIDE_RECEIPT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "override_receipt_id",
    "run_id",
    "lane_id",
    "override_kind",
    "override_reason",
    "evidence_paths",
    "attestation_mode",
    "signoffs",
    "created_at",
)
_OPTIONAL_ORDER = ("notes",)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)
_HASH_DROP_KEYS = {"created_at", "override_receipt_id"}


def validate_fl3_human_override_receipt(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="human_override_receipt")
    enforce_max_fields(entry, max_fields=256)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_HUMAN_OVERRIDE_RECEIPT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_HUMAN_OVERRIDE_RECEIPT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "override_receipt_id")
    validate_created_at_utc_z(entry.get("created_at"))
    validate_short_string(entry, "run_id", max_len=128)
    validate_short_string(entry, "lane_id", max_len=64)
    validate_short_string(entry, "override_kind", max_len=64)
    validate_short_string(entry, "override_reason", max_len=8192)
    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    mode = str(entry.get("attestation_mode", "")).strip().upper()
    if mode not in {"SIMULATED", "HMAC", "PKI"}:
        raise SchemaValidationError("attestation_mode invalid (fail-closed)")

    _ = ensure_sorted_str_list(entry.get("evidence_paths"), field="evidence_paths")

    signoffs = entry.get("signoffs")
    if not isinstance(signoffs, list) or len(signoffs) < 2:
        raise SchemaValidationError("signoffs must be a list with >=2 entries (fail-closed)")
    key_ids: List[str] = []
    for s in signoffs:
        sd = require_dict(s, name="Signoff")
        validate_fl3_human_signoff_v2(sd)
        if str(sd.get("attestation_mode")) != mode:
            raise SchemaValidationError("signoff attestation_mode mismatch vs receipt attestation_mode (fail-closed)")
        key_ids.append(str(sd.get("key_id", "")).strip())
    if len(set(key_ids)) < 2:
        raise SchemaValidationError("signoffs must include two distinct key_id values (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("override_receipt_id") != expected:
        raise SchemaValidationError("override_receipt_id does not match canonical hash surface (fail-closed)")

