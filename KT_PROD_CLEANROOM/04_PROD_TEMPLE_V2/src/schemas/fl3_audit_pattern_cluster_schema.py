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


FL3_AUDIT_PATTERN_CLUSTER_SCHEMA_ID = "kt.audit_pattern_cluster.v1"
FL3_AUDIT_PATTERN_CLUSTER_SCHEMA_FILE = "fl3/kt.audit_pattern_cluster.v1.json"
FL3_AUDIT_PATTERN_CLUSTER_SCHEMA_VERSION_HASH = schema_version_hash(FL3_AUDIT_PATTERN_CLUSTER_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "cluster_id",
    "reason_code",
    "event_ids",
    "count",
    "created_at",
)
_OPTIONAL_ORDER = ("notes",)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)


def validate_fl3_audit_pattern_cluster(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 audit pattern cluster")
    enforce_max_fields(entry, max_fields=24)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_AUDIT_PATTERN_CLUSTER_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_AUDIT_PATTERN_CLUSTER_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "cluster_id")
    validate_short_string(entry, "reason_code", max_len=128)
    validate_created_at_utc_z(entry.get("created_at"))

    event_ids = entry.get("event_ids")
    if not isinstance(event_ids, list) or not event_ids:
        raise SchemaValidationError("event_ids must be non-empty list (fail-closed)")
    prev = None
    for x in event_ids:
        if not isinstance(x, str):
            raise SchemaValidationError("event_ids entries must be strings (fail-closed)")
        validate_hex_64({"event_id": x}, "event_id")
        if prev is not None and x < prev:
            raise SchemaValidationError("event_ids must be sorted (fail-closed)")
        prev = x

    count = entry.get("count")
    if not isinstance(count, int) or count < 1:
        raise SchemaValidationError("count must be int >= 1 (fail-closed)")
    if int(count) != len(event_ids):
        raise SchemaValidationError("count must equal len(event_ids) (fail-closed)")

    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    expected_id = sha256_hex_of_obj(entry, drop_keys={"created_at", "cluster_id"})
    if entry.get("cluster_id") != expected_id:
        raise SchemaValidationError("cluster_id does not match canonical hash surface (fail-closed)")

