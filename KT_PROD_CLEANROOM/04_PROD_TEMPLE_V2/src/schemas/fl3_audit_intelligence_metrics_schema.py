from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_hex_64,
)
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_AUDIT_INTELLIGENCE_METRICS_SCHEMA_ID = "kt.audit_intelligence_metrics.v1"
FL3_AUDIT_INTELLIGENCE_METRICS_SCHEMA_FILE = "fl3/kt.audit_intelligence_metrics.v1.json"
FL3_AUDIT_INTELLIGENCE_METRICS_SCHEMA_VERSION_HASH = schema_version_hash(FL3_AUDIT_INTELLIGENCE_METRICS_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "metrics_id",
    "report_id",
    "counts",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)


def validate_fl3_audit_intelligence_metrics(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 audit intelligence metrics")
    enforce_max_fields(entry, max_fields=24)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_AUDIT_INTELLIGENCE_METRICS_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_AUDIT_INTELLIGENCE_METRICS_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "metrics_id")
    validate_hex_64(entry, "report_id")
    validate_created_at_utc_z(entry.get("created_at"))

    counts = entry.get("counts")
    if not isinstance(counts, dict):
        raise SchemaValidationError("counts must be object (fail-closed)")
    required = {"events_ingested", "clusters", "probe_proposals", "doctrine_proposals"}
    if set(counts.keys()) != required:
        raise SchemaValidationError("counts keys mismatch (fail-closed)")
    for k in required:
        v = counts.get(k)
        if not isinstance(v, int) or v < 0:
            raise SchemaValidationError("counts values must be int >= 0 (fail-closed)")

    expected_id = sha256_hex_of_obj(entry, drop_keys={"created_at", "metrics_id"})
    if entry.get("metrics_id") != expected_id:
        raise SchemaValidationError("metrics_id does not match canonical hash surface (fail-closed)")

