from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_SCORING_SPEC_SCHEMA_ID = "kt.scoring_spec.v1"
FL3_SCORING_SPEC_SCHEMA_FILE = "fl3/kt.scoring_spec.v1.json"
FL3_SCORING_SPEC_SCHEMA_VERSION_HASH = schema_version_hash(FL3_SCORING_SPEC_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "spec_id",
    "metrics",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "spec_id"}


def validate_fl3_scoring_spec(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="scoring_spec")
    enforce_max_fields(entry, max_fields=64)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_SCORING_SPEC_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_SCORING_SPEC_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "spec_id")
    validate_created_at_utc_z(entry.get("created_at"))

    metrics = entry.get("metrics")
    if not isinstance(metrics, list) or len(metrics) < 1:
        raise SchemaValidationError("metrics must be non-empty list (fail-closed)")
    for m in metrics:
        if not isinstance(m, dict):
            raise SchemaValidationError("metrics entries must be objects (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("spec_id") != expected:
        raise SchemaValidationError("spec_id does not match canonical hash surface (fail-closed)")

