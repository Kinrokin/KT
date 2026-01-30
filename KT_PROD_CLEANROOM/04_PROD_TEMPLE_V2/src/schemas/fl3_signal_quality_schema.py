from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64, validate_short_string
from schemas.fl3_schema_common import validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_SIGNAL_QUALITY_SCHEMA_ID = "kt.signal_quality.v1"
FL3_SIGNAL_QUALITY_SCHEMA_FILE = "fl3/kt.signal_quality.v1.json"
FL3_SIGNAL_QUALITY_SCHEMA_VERSION_HASH = schema_version_hash(FL3_SIGNAL_QUALITY_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "adapter_id",
    "adapter_version",
    "risk_estimate",
    "governance_strikes",
    "status",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)


def validate_fl3_signal_quality(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 signal quality")
    enforce_max_fields(entry, max_fields=32)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_SIGNAL_QUALITY_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_SIGNAL_QUALITY_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")
    validate_hex_64(entry, "schema_version_hash")

    validate_short_string(entry, "adapter_id", max_len=128)
    validate_short_string(entry, "adapter_version", max_len=64)
    validate_created_at_utc_z(entry.get("created_at"))

    risk = entry.get("risk_estimate")
    if not isinstance(risk, (int, float)) or risk < 0.0 or risk > 1.0:
        raise SchemaValidationError("risk_estimate must be in [0,1] (fail-closed)")
    strikes = entry.get("governance_strikes")
    if not isinstance(strikes, int) or strikes < 0:
        raise SchemaValidationError("governance_strikes must be >=0 integer (fail-closed)")
    status = entry.get("status")
    if status not in {"CANDIDATE", "QUARANTINED", "PROMOTED"}:
        raise SchemaValidationError("status must be CANDIDATE, QUARANTINED, or PROMOTED (fail-closed)")

