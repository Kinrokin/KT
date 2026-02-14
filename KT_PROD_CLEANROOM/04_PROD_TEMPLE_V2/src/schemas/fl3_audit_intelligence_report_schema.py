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


FL3_AUDIT_INTELLIGENCE_REPORT_SCHEMA_ID = "kt.audit_intelligence_report.v1"
FL3_AUDIT_INTELLIGENCE_REPORT_SCHEMA_FILE = "fl3/kt.audit_intelligence_report.v1.json"
FL3_AUDIT_INTELLIGENCE_REPORT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_AUDIT_INTELLIGENCE_REPORT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "report_id",
    "vault_root_rel",
    "config_id",
    "ingested_events",
    "clusters",
    "probe_proposals",
    "doctrine_proposals",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)


def _validate_sorted_hex64_list(value: Any, *, field: str) -> None:
    if not isinstance(value, list):
        raise SchemaValidationError(f"{field} must be a list (fail-closed)")
    stripped = []
    for x in value:
        if not isinstance(x, str):
            raise SchemaValidationError(f"{field} entries must be strings (fail-closed)")
        validate_hex_64({"h": x}, "h")
        stripped.append(x)
    if stripped != sorted(stripped):
        raise SchemaValidationError(f"{field} must be sorted (fail-closed)")


def validate_fl3_audit_intelligence_report(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 audit intelligence report")
    enforce_max_fields(entry, max_fields=24)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_AUDIT_INTELLIGENCE_REPORT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_AUDIT_INTELLIGENCE_REPORT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "report_id")
    validate_hex_64(entry, "config_id")
    validate_short_string(entry, "vault_root_rel", max_len=1024)
    validate_created_at_utc_z(entry.get("created_at"))

    ie = entry.get("ingested_events")
    if not isinstance(ie, int) or ie < 0:
        raise SchemaValidationError("ingested_events must be int >= 0 (fail-closed)")

    _validate_sorted_hex64_list(entry.get("clusters"), field="clusters")
    _validate_sorted_hex64_list(entry.get("probe_proposals"), field="probe_proposals")
    _validate_sorted_hex64_list(entry.get("doctrine_proposals"), field="doctrine_proposals")

    expected_id = sha256_hex_of_obj(entry, drop_keys={"created_at", "report_id"})
    if entry.get("report_id") != expected_id:
        raise SchemaValidationError("report_id does not match canonical hash surface (fail-closed)")

