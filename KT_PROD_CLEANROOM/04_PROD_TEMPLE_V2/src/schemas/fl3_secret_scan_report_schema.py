from __future__ import annotations

from typing import Any, Dict, List, Set

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


FL3_SECRET_SCAN_REPORT_SCHEMA_ID = "kt.secret_scan_report.v1"
FL3_SECRET_SCAN_REPORT_SCHEMA_FILE = "fl3/kt.secret_scan_report.v1.json"
FL3_SECRET_SCAN_REPORT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_SECRET_SCAN_REPORT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "report_id",
    "status",
    "scanner_version",
    "patterns_version",
    "findings",
    "report_hash",
    "created_at",
)
_OPTIONAL_ORDER = (
    "run_id",
    "lane_id",
    "notes",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)


def _validate_finding(obj: Any) -> None:
    entry = require_dict(obj, name="secret_scan.findings[]")
    required = {"finding_id", "path_rel", "reason", "confidence", "snippet_redacted", "snippet_sha256"}
    allowed = set(required) | {"line", "column", "pattern_id"}
    require_keys(entry, required=required)
    reject_unknown_keys(entry, allowed=allowed)

    validate_hex_64(entry, "finding_id")
    validate_short_string(entry, "path_rel", max_len=2048)
    validate_short_string(entry, "reason", max_len=64)
    validate_short_string(entry, "confidence", max_len=16)
    validate_short_string(entry, "snippet_redacted", max_len=256)
    validate_hex_64(entry, "snippet_sha256")

    if entry.get("reason") not in {"REGEX", "DECODED_REGEX", "HIGH_ENTROPY", "ENCODED_HIGH_ENTROPY", "READ_ERROR"}:
        raise SchemaValidationError("finding.reason invalid (fail-closed)")
    if entry.get("confidence") not in {"HIGH", "MEDIUM", "LOW"}:
        raise SchemaValidationError("finding.confidence invalid (fail-closed)")

    if "pattern_id" in entry and entry["pattern_id"] is not None:
        validate_short_string(entry, "pattern_id", max_len=128)
    if "line" in entry and entry["line"] is not None:
        if not isinstance(entry["line"], int) or entry["line"] < 1:
            raise SchemaValidationError("finding.line must be integer >= 1 (fail-closed)")
    if "column" in entry and entry["column"] is not None:
        if not isinstance(entry["column"], int) or entry["column"] < 1:
            raise SchemaValidationError("finding.column must be integer >= 1 (fail-closed)")


def validate_fl3_secret_scan_report(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 secret scan report")
    enforce_max_fields(entry, max_fields=2000)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    enforce_max_canonical_json_bytes(entry, max_bytes=512 * 1024)

    if entry.get("schema_id") != FL3_SECRET_SCAN_REPORT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_SECRET_SCAN_REPORT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "report_id")
    validate_hex_64(entry, "report_hash")
    validate_short_string(entry, "status", max_len=16)
    validate_short_string(entry, "scanner_version", max_len=64)
    validate_short_string(entry, "patterns_version", max_len=64)
    validate_created_at_utc_z(entry.get("created_at"))

    if entry.get("status") not in {"PASS", "FAIL", "ERROR"}:
        raise SchemaValidationError("status must be PASS, FAIL, or ERROR (fail-closed)")

    if "run_id" in entry:
        validate_short_string(entry, "run_id", max_len=128)
    if "lane_id" in entry:
        validate_short_string(entry, "lane_id", max_len=64)
    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    findings = entry.get("findings")
    if not isinstance(findings, list):
        raise SchemaValidationError("findings must be a list (fail-closed)")
    for f in findings:
        _validate_finding(f)

    expected_id = sha256_hex_of_obj(
        entry,
        drop_keys={"created_at", "report_id", "report_hash"},
    )
    if entry.get("report_id") != expected_id:
        raise SchemaValidationError("report_id does not match canonical hash surface (fail-closed)")

    expected_hash = sha256_hex_of_obj(entry, drop_keys={"report_hash"})
    if entry.get("report_hash") != expected_hash:
        raise SchemaValidationError("report_hash does not match canonical payload (fail-closed)")

