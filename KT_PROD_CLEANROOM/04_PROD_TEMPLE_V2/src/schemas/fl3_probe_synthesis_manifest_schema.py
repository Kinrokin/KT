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


FL3_PROBE_SYNTHESIS_MANIFEST_SCHEMA_ID = "kt.probe_synthesis_manifest.v1"
FL3_PROBE_SYNTHESIS_MANIFEST_SCHEMA_FILE = "fl3/kt.probe_synthesis_manifest.v1.json"
FL3_PROBE_SYNTHESIS_MANIFEST_SCHEMA_VERSION_HASH = schema_version_hash(FL3_PROBE_SYNTHESIS_MANIFEST_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "manifest_id",
    "vault_root_rel",
    "event_count",
    "min_support",
    "created_at",
)
_OPTIONAL_ORDER = ("notes",)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)
_HASH_DROP_KEYS = {"created_at", "manifest_id"}


def validate_fl3_probe_synthesis_manifest(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="probe_synthesis_manifest")
    enforce_max_fields(entry, max_fields=64)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_PROBE_SYNTHESIS_MANIFEST_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_PROBE_SYNTHESIS_MANIFEST_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "manifest_id")
    validate_created_at_utc_z(entry.get("created_at"))

    validate_short_string(entry, "vault_root_rel", max_len=2048)
    if not isinstance(entry.get("event_count"), int) or int(entry.get("event_count")) < 0:
        raise SchemaValidationError("event_count must be integer >= 0 (fail-closed)")
    if not isinstance(entry.get("min_support"), int) or int(entry.get("min_support")) < 1:
        raise SchemaValidationError("min_support must be integer >= 1 (fail-closed)")
    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("manifest_id") != expected:
        raise SchemaValidationError("manifest_id does not match canonical hash surface (fail-closed)")

