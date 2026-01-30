from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_canonical_json_bytes,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_bounded_json_value,
    validate_hex_64,
)
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_CANARY_ARTIFACT_SCHEMA_ID = "kt.canary_artifact.v1"
FL3_CANARY_ARTIFACT_SCHEMA_FILE = "fl3/kt.canary_artifact.v1.json"
FL3_CANARY_ARTIFACT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_CANARY_ARTIFACT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "canary_id",
    "git_sha",
    "platform_fingerprint",
    "law_bundle_hash",
    "determinism_contract_hash",
    "supported_platforms_hash",
    "utility_pack_hash",
    "job_dir_manifest_schema_hash",
    "hash_manifest_root_hash",
    "canary_job_id",
    "canary_result",
    "payload_hash",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "canary_id"}


def validate_fl3_canary_artifact(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL4 canary artifact")
    enforce_max_fields(entry, max_fields=64)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    enforce_max_canonical_json_bytes(entry, max_bytes=256 * 1024)

    if entry.get("schema_id") != FL3_CANARY_ARTIFACT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_CANARY_ARTIFACT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "canary_id")
    validate_hex_64(entry, "law_bundle_hash")
    validate_hex_64(entry, "determinism_contract_hash")
    validate_hex_64(entry, "supported_platforms_hash")
    validate_hex_64(entry, "utility_pack_hash")
    validate_hex_64(entry, "job_dir_manifest_schema_hash")
    validate_hex_64(entry, "hash_manifest_root_hash")
    validate_hex_64(entry, "canary_job_id")
    validate_hex_64(entry, "payload_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    if entry.get("canary_result") not in {"PASS", "FAIL"}:
        raise SchemaValidationError("canary_result invalid (fail-closed)")

    pf = require_dict(entry.get("platform_fingerprint"), name="platform_fingerprint")
    validate_bounded_json_value(pf, max_depth=8, max_string_len=4096, max_list_len=256)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("canary_id") != expected:
        raise SchemaValidationError("canary_id does not match canonical hash surface (fail-closed)")

