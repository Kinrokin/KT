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


FL3_AUDIT_INTELLIGENCE_CONFIG_SCHEMA_ID = "kt.audit_intelligence_config.v1"
FL3_AUDIT_INTELLIGENCE_CONFIG_SCHEMA_FILE = "fl3/kt.audit_intelligence_config.v1.json"
FL3_AUDIT_INTELLIGENCE_CONFIG_SCHEMA_VERSION_HASH = schema_version_hash(FL3_AUDIT_INTELLIGENCE_CONFIG_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "config_id",
    "min_cluster_size",
    "proposal_cooldown_hours",
    "created_at",
)
_OPTIONAL_ORDER = ("reason_code_allowlist",)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)


def validate_fl3_audit_intelligence_config(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 audit intelligence config")
    enforce_max_fields(entry, max_fields=24)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_AUDIT_INTELLIGENCE_CONFIG_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_AUDIT_INTELLIGENCE_CONFIG_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "config_id")
    validate_created_at_utc_z(entry.get("created_at"))

    mcs = entry.get("min_cluster_size")
    if not isinstance(mcs, int) or mcs < 1:
        raise SchemaValidationError("min_cluster_size must be int >= 1 (fail-closed)")
    cd = entry.get("proposal_cooldown_hours")
    if not isinstance(cd, int) or cd < 0:
        raise SchemaValidationError("proposal_cooldown_hours must be int >= 0 (fail-closed)")

    if "reason_code_allowlist" in entry:
        rca = entry.get("reason_code_allowlist")
        if not isinstance(rca, list):
            raise SchemaValidationError("reason_code_allowlist must be a list (fail-closed)")
        stripped = []
        for x in rca:
            if not isinstance(x, str) or not x.strip():
                raise SchemaValidationError("reason_code_allowlist must contain non-empty strings (fail-closed)")
            stripped.append(x.strip())
        if stripped != sorted(stripped):
            raise SchemaValidationError("reason_code_allowlist must be sorted (fail-closed)")

    expected_id = sha256_hex_of_obj(entry, drop_keys={"created_at", "config_id"})
    if entry.get("config_id") != expected_id:
        raise SchemaValidationError("config_id does not match canonical hash surface (fail-closed)")

