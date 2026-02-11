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


FL3_EPIGENETIC_SUMMARY_SCHEMA_ID = "kt.epigenetic_summary.v1"
FL3_EPIGENETIC_SUMMARY_SCHEMA_FILE = "fl3/kt.epigenetic_summary.v1.json"
FL3_EPIGENETIC_SUMMARY_SCHEMA_VERSION_HASH = schema_version_hash(FL3_EPIGENETIC_SUMMARY_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "summary_id",
    "paradox_survival_count",
    "recovery_efficiency",
    "lineage_weight",
    "signed_by",
    "parent_hash",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "summary_id"}


def validate_fl3_epigenetic_summary(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 epigenetic summary")
    enforce_max_fields(entry, max_fields=32)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_EPIGENETIC_SUMMARY_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_EPIGENETIC_SUMMARY_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")
    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "summary_id")
    validate_hex_64(entry, "parent_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    count = entry.get("paradox_survival_count")
    if not isinstance(count, int) or count < 0:
        raise SchemaValidationError("paradox_survival_count must be >=0 int (fail-closed)")
    for f in ("recovery_efficiency", "lineage_weight"):
        v = entry.get(f)
        if not isinstance(v, (int, float)) or v < 0.0 or v > 1.0:
            raise SchemaValidationError(f"{f} must be in [0,1] (fail-closed)")
    validate_short_string(entry, "signed_by", max_len=128)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("summary_id") != expected:
        raise SchemaValidationError("summary_id does not match canonical hash surface (fail-closed)")

