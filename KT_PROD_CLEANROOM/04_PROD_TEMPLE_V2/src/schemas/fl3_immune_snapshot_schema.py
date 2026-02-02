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


FL3_IMMUNE_SNAPSHOT_SCHEMA_ID = "kt.immune_snapshot.v1"
FL3_IMMUNE_SNAPSHOT_SCHEMA_FILE = "fl3/kt.immune_snapshot.v1.json"
FL3_IMMUNE_SNAPSHOT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_IMMUNE_SNAPSHOT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "snapshot_id",
    "immune_events_total",
    "counts",
    "parent_hash",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "snapshot_id"}


def validate_fl3_immune_snapshot(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 immune snapshot")
    enforce_max_fields(entry, max_fields=32)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_IMMUNE_SNAPSHOT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_IMMUNE_SNAPSHOT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")
    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "snapshot_id")
    validate_hex_64(entry, "parent_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    total = entry.get("immune_events_total")
    if not isinstance(total, int) or total < 0:
        raise SchemaValidationError("immune_events_total must be >=0 int (fail-closed)")
    counts = require_dict(entry.get("counts"), name="counts")
    require_keys(counts, required={"paradox_event", "trace_violation", "schema_violation"})
    reject_unknown_keys(counts, allowed={"paradox_event", "trace_violation", "schema_violation"})
    for k in ("paradox_event", "trace_violation", "schema_violation"):
        v = counts.get(k)
        if not isinstance(v, int) or v < 0:
            raise SchemaValidationError("counts must be >=0 ints (fail-closed)")
    if total != int(counts["paradox_event"]) + int(counts["trace_violation"]) + int(counts["schema_violation"]):
        raise SchemaValidationError("immune_events_total mismatch (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("snapshot_id") != expected:
        raise SchemaValidationError("snapshot_id does not match canonical hash surface (fail-closed)")

