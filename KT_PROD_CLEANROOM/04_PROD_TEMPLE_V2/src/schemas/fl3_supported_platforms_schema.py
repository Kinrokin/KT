from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64, validate_short_string
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_SUPPORTED_PLATFORMS_SCHEMA_ID = "kt.supported_platforms.v1"
FL3_SUPPORTED_PLATFORMS_SCHEMA_FILE = "fl3/kt.supported_platforms.v1.json"
FL3_SUPPORTED_PLATFORMS_SCHEMA_VERSION_HASH = schema_version_hash(FL3_SUPPORTED_PLATFORMS_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "supported_platforms_id",
    "seal_claim_scope",
    "os",
    "python",
    "hashing",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {
    "numpy",
    "torch_cpu",
    "container_image_sha256",
    "env",
    "io_normalization",
    "filesystem",
}
_HASH_DROP_KEYS = {"created_at", "supported_platforms_id"}


def validate_fl3_supported_platforms(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="supported_platforms")
    enforce_max_fields(entry, max_fields=64)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_SUPPORTED_PLATFORMS_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_SUPPORTED_PLATFORMS_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "supported_platforms_id")
    validate_short_string(entry, "seal_claim_scope", max_len=512)
    validate_short_string(entry, "os", max_len=128)
    validate_short_string(entry, "python", max_len=64)
    validate_created_at_utc_z(entry.get("created_at"))

    hashing = require_dict(entry.get("hashing"), name="hashing")
    if set(hashing.keys()) != {"sha"}:
        raise SchemaValidationError("hashing must have sha only (fail-closed)")
    if hashing.get("sha") != "sha256":
        raise SchemaValidationError("hashing.sha must be sha256 (fail-closed)")

    cis = entry.get("container_image_sha256")
    if cis is not None:
        if not isinstance(cis, str) or not cis.startswith("sha256:") or len(cis) != 71:
            raise SchemaValidationError("container_image_sha256 invalid (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("supported_platforms_id") != expected:
        raise SchemaValidationError("supported_platforms_id does not match canonical hash surface (fail-closed)")

