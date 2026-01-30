from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64, validate_short_string
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_PROMOTED_MANIFEST_SCHEMA_ID = "kt.promoted_manifest.v1"
FL3_PROMOTED_MANIFEST_SCHEMA_FILE = "fl3/kt.promoted_manifest.v1.json"
FL3_PROMOTED_MANIFEST_SCHEMA_VERSION_HASH = schema_version_hash(FL3_PROMOTED_MANIFEST_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "promoted_manifest_id",
    "adapter_id",
    "adapter_version",
    "content_hash",
    "job_id",
    "canary_hash_manifest_root_hash",
    "canary_artifact_hash",
    "hash_manifest_root_hash",
    "parent_hash",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "promoted_manifest_id"}


def validate_fl3_promoted_manifest(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="promoted_manifest")
    enforce_max_fields(entry, max_fields=64)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_PROMOTED_MANIFEST_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_PROMOTED_MANIFEST_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "promoted_manifest_id")
    validate_short_string(entry, "adapter_id", max_len=128)
    validate_short_string(entry, "adapter_version", max_len=64)
    for k in ("content_hash", "job_id", "canary_hash_manifest_root_hash", "canary_artifact_hash", "hash_manifest_root_hash", "parent_hash"):
        validate_hex_64(entry, k)
    validate_created_at_utc_z(entry.get("created_at"))

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("promoted_manifest_id") != expected:
        raise SchemaValidationError("promoted_manifest_id does not match canonical hash surface (fail-closed)")


