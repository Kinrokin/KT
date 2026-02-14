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
from schemas.fl3_schema_common import ensure_sorted_str_list, sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_PROMOTION_RATIONALE_SCHEMA_ID = "kt.promotion_rationale.v1"
FL3_PROMOTION_RATIONALE_SCHEMA_FILE = "fl3/kt.promotion_rationale.v1.json"
FL3_PROMOTION_RATIONALE_SCHEMA_VERSION_HASH = schema_version_hash(FL3_PROMOTION_RATIONALE_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "rationale_id",
    "job_id",
    "lane_id",
    "decision",
    "summary",
    "evidence_paths",
    "created_at",
)
_OPTIONAL_ORDER = ("notes",)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)
_HASH_DROP_KEYS = {"created_at", "rationale_id"}


def validate_fl3_promotion_rationale(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="promotion_rationale")
    enforce_max_fields(entry, max_fields=128)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_PROMOTION_RATIONALE_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_PROMOTION_RATIONALE_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "rationale_id")
    validate_created_at_utc_z(entry.get("created_at"))

    validate_short_string(entry, "job_id", max_len=128)
    validate_short_string(entry, "lane_id", max_len=64)
    decision = str(entry.get("decision", "")).strip().upper()
    if decision not in {"PROMOTE", "NO_PROMOTE", "BLOCK", "UNKNOWN"}:
        raise SchemaValidationError("decision invalid (fail-closed)")
    validate_short_string(entry, "summary", max_len=8192)
    _ = ensure_sorted_str_list(entry.get("evidence_paths"), field="evidence_paths")
    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("rationale_id") != expected:
        raise SchemaValidationError("rationale_id does not match canonical hash surface (fail-closed)")

