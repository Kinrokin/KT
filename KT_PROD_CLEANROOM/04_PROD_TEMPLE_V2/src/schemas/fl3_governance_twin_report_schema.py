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
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_GOVERNANCE_TWIN_REPORT_SCHEMA_ID = "kt.governance_twin_report.v1"
FL3_GOVERNANCE_TWIN_REPORT_SCHEMA_FILE = "fl3/kt.governance_twin_report.v1.json"
FL3_GOVERNANCE_TWIN_REPORT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_GOVERNANCE_TWIN_REPORT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "twin_report_id",
    "twin_manifest_id",
    "run_id",
    "lane_id",
    "status",
    "reason_codes",
    "mismatches",
    "created_at",
)
_OPTIONAL_ORDER = ("notes",)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)
_HASH_DROP_KEYS = {"created_at", "twin_report_id"}


def _validate_reason_codes(value: Any) -> List[str]:
    if not isinstance(value, list):
        raise SchemaValidationError("reason_codes must be list (fail-closed)")
    out = [str(x).strip() for x in value if isinstance(x, str) and str(x).strip()]
    if out != sorted(out):
        raise SchemaValidationError("reason_codes must be sorted (fail-closed)")
    if len(set(out)) != len(out):
        raise SchemaValidationError("reason_codes must be unique (fail-closed)")
    return out


def _validate_mismatches(value: Any) -> List[Dict[str, str]]:
    if not isinstance(value, list):
        raise SchemaValidationError("mismatches must be list (fail-closed)")
    out: List[Dict[str, str]] = []
    for item in value:
        row = require_dict(item, name="mismatches[]")
        require_keys(row, required={"field", "expected", "actual"})
        reject_unknown_keys(row, allowed={"field", "expected", "actual"})
        field = str(row.get("field", "")).strip()
        if not field:
            raise SchemaValidationError("mismatches[].field must be non-empty (fail-closed)")
        expected = str(row.get("expected", ""))
        actual = str(row.get("actual", ""))
        validate_short_string({"field": field}, "field", max_len=256)
        validate_short_string({"expected": expected}, "expected", max_len=4096)
        validate_short_string({"actual": actual}, "actual", max_len=4096)
        out.append({"field": field, "expected": expected, "actual": actual})
    fields = [r["field"] for r in out]
    if fields != sorted(fields):
        raise SchemaValidationError("mismatches must be sorted by field (fail-closed)")
    if len(set(fields)) != len(fields):
        raise SchemaValidationError("mismatches.field must be unique (fail-closed)")
    return out


def validate_fl3_governance_twin_report(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="governance_twin_report")
    enforce_max_fields(entry, max_fields=512)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_GOVERNANCE_TWIN_REPORT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_GOVERNANCE_TWIN_REPORT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "twin_report_id")
    validate_hex_64(entry, "twin_manifest_id")
    validate_created_at_utc_z(entry.get("created_at"))

    validate_short_string(entry, "run_id", max_len=128)
    validate_short_string(entry, "lane_id", max_len=64)
    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    status = entry.get("status")
    if status not in {"PASS", "FAIL_CLOSED"}:
        raise SchemaValidationError("status must be PASS or FAIL_CLOSED (fail-closed)")

    reason_codes = _validate_reason_codes(entry.get("reason_codes"))
    mismatches = _validate_mismatches(entry.get("mismatches"))

    if status == "PASS":
        if reason_codes or mismatches:
            raise SchemaValidationError("PASS report must have empty reason_codes and mismatches (fail-closed)")
    else:
        if not reason_codes or not mismatches:
            raise SchemaValidationError("FAIL_CLOSED report must include reason_codes and mismatches (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("twin_report_id") != expected:
        raise SchemaValidationError("twin_report_id does not match canonical hash surface (fail-closed)")

