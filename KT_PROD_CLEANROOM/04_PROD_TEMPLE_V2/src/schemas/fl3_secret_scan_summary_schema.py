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


FL3_SECRET_SCAN_SUMMARY_SCHEMA_ID = "kt.secret_scan_summary.v1"
FL3_SECRET_SCAN_SUMMARY_SCHEMA_FILE = "fl3/kt.secret_scan_summary.v1.json"
FL3_SECRET_SCAN_SUMMARY_SCHEMA_VERSION_HASH = schema_version_hash(FL3_SECRET_SCAN_SUMMARY_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "summary_id",
    "report_hash",
    "status",
    "total_findings",
    "high_confidence_findings",
    "created_at",
)
_OPTIONAL_ORDER = (
    "run_id",
    "lane_id",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)


def validate_fl3_secret_scan_summary(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 secret scan summary")
    enforce_max_fields(entry, max_fields=64)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    enforce_max_canonical_json_bytes(entry, max_bytes=64 * 1024)

    if entry.get("schema_id") != FL3_SECRET_SCAN_SUMMARY_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_SECRET_SCAN_SUMMARY_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "summary_id")
    validate_hex_64(entry, "report_hash")
    validate_short_string(entry, "status", max_len=16)
    validate_created_at_utc_z(entry.get("created_at"))

    if entry.get("status") not in {"PASS", "FAIL", "ERROR"}:
        raise SchemaValidationError("status must be PASS, FAIL, or ERROR (fail-closed)")

    for f in ("total_findings", "high_confidence_findings"):
        v = entry.get(f)
        if not isinstance(v, int) or v < 0:
            raise SchemaValidationError(f"{f} must be integer >= 0 (fail-closed)")

    if "run_id" in entry:
        validate_short_string(entry, "run_id", max_len=128)
    if "lane_id" in entry:
        validate_short_string(entry, "lane_id", max_len=64)

    expected = sha256_hex_of_obj(entry, drop_keys={"created_at", "summary_id"})
    if entry.get("summary_id") != expected:
        raise SchemaValidationError("summary_id does not match canonical hash surface (fail-closed)")

