from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64, validate_short_string
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_REVEAL_MAPPING_SCHEMA_ID = "kt.reveal_mapping.v1"
FL3_REVEAL_MAPPING_SCHEMA_FILE = "fl3/kt.reveal_mapping.v1.json"
FL3_REVEAL_MAPPING_SCHEMA_VERSION_HASH = schema_version_hash(FL3_REVEAL_MAPPING_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "mapping_id",
    "job_id",
    "sealed",
    "verdict_ref",
    "mappings",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "mapping_id"}


def validate_fl3_reveal_mapping(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 reveal mapping")
    enforce_max_fields(entry, max_fields=32)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_REVEAL_MAPPING_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_REVEAL_MAPPING_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "mapping_id")
    validate_hex_64(entry, "job_id")
    validate_created_at_utc_z(entry.get("created_at"))

    sealed = entry.get("sealed")
    if not isinstance(sealed, bool):
        raise SchemaValidationError("sealed must be boolean (fail-closed)")

    verdict_ref = entry.get("verdict_ref")
    if verdict_ref is not None:
        validate_short_string(entry, "verdict_ref", max_len=256)
    else:
        if not sealed:
            raise SchemaValidationError("verdict_ref cannot be null when sealed=false (fail-closed)")

    mappings = entry.get("mappings")
    if not isinstance(mappings, dict):
        raise SchemaValidationError("mappings must be an object (fail-closed)")
    for k, v in mappings.items():
        if not isinstance(k, str) or not k or len(k) > 128:
            raise SchemaValidationError("mappings keys must be short non-empty strings (fail-closed)")
        mv = require_dict(v, name="Reveal mapping value")
        # Ensure identity lives only here (not in blind pack).
        required = {"adapter_id", "adapter_version"}
        if not required.issubset(mv.keys()):
            raise SchemaValidationError("reveal mapping values must include adapter_id and adapter_version (fail-closed)")
        if not isinstance(mv.get("adapter_id"), str) or not mv["adapter_id"].strip():
            raise SchemaValidationError("adapter_id must be a non-empty string (fail-closed)")
        if not isinstance(mv.get("adapter_version"), str) or not mv["adapter_version"].strip():
            raise SchemaValidationError("adapter_version must be a non-empty string (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("mapping_id") != expected:
        raise SchemaValidationError("mapping_id does not match canonical hash surface (fail-closed)")

