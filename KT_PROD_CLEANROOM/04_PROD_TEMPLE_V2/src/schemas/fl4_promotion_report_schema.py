from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_canonical_json_bytes,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_hex_64,
    validate_short_string,
)
from schemas.schema_files import schema_version_hash


FL4_PROMOTION_REPORT_SCHEMA_ID = "kt.fl4.promotion_report.v1"
FL4_PROMOTION_REPORT_SCHEMA_FILE = "fl3/kt.fl4.promotion_report.v1.json"
FL4_PROMOTION_REPORT_SCHEMA_VERSION_HASH = schema_version_hash(FL4_PROMOTION_REPORT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "job_dir",
    "promoted_dir",
    "promoted_index_path",
    "content_hash",
    "promoted_manifest_id",
    "promoted_manifest_sha256",
    "canary_artifact_hash",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)


def validate_fl4_promotion_report(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL4 promotion report")
    enforce_max_fields(entry, max_fields=24)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    enforce_max_canonical_json_bytes(entry, max_bytes=64 * 1024)

    if entry.get("schema_id") != FL4_PROMOTION_REPORT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL4_PROMOTION_REPORT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_short_string(entry, "job_dir", max_len=1024)
    validate_short_string(entry, "promoted_dir", max_len=1024)
    validate_short_string(entry, "promoted_index_path", max_len=1024)
    validate_hex_64(entry, "content_hash")
    validate_hex_64(entry, "promoted_manifest_id")
    validate_hex_64(entry, "promoted_manifest_sha256")
    validate_hex_64(entry, "canary_artifact_hash")

