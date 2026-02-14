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
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_DELIVERY_PACK_MANIFEST_SCHEMA_ID = "kt.delivery_pack_manifest.v1"
FL3_DELIVERY_PACK_MANIFEST_SCHEMA_FILE = "fl3/kt.delivery_pack_manifest.v1.json"
FL3_DELIVERY_PACK_MANIFEST_SCHEMA_VERSION_HASH = schema_version_hash(FL3_DELIVERY_PACK_MANIFEST_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "delivery_pack_id",
    "run_id",
    "bundle_root_hash",
    "run_protocol_json_hash",
    "redaction_rules_version",
    "files",
    "created_at",
)
_OPTIONAL_ORDER = ("notes",)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)


def _validate_file_entry(obj: Any) -> str:
    entry = require_dict(obj, name="delivery_pack.files[]")
    require_keys(entry, required={"path", "sha256", "bytes", "redacted"})
    reject_unknown_keys(entry, allowed={"path", "sha256", "bytes", "redacted"})

    path = entry.get("path")
    if not isinstance(path, str) or not path.strip():
        raise SchemaValidationError("files[].path must be non-empty string (fail-closed)")
    rel = path.strip()
    if rel.startswith("/") or ".." in rel.split("/"):
        raise SchemaValidationError("files[].path must be clean relative path (fail-closed)")
    validate_short_string({"path": rel}, "path", max_len=2048)
    validate_hex_64(entry, "sha256")

    b = entry.get("bytes")
    if not isinstance(b, int) or b < 0:
        raise SchemaValidationError("files[].bytes must be non-negative int (fail-closed)")
    if not isinstance(entry.get("redacted"), bool):
        raise SchemaValidationError("files[].redacted must be boolean (fail-closed)")

    return rel


def validate_fl3_delivery_pack_manifest(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 delivery pack manifest")
    enforce_max_fields(entry, max_fields=32)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    enforce_max_canonical_json_bytes(entry, max_bytes=512 * 1024)

    if entry.get("schema_id") != FL3_DELIVERY_PACK_MANIFEST_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_DELIVERY_PACK_MANIFEST_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "delivery_pack_id")
    validate_hex_64(entry, "bundle_root_hash")
    validate_hex_64(entry, "run_protocol_json_hash")

    validate_short_string(entry, "run_id", max_len=128)
    validate_short_string(entry, "redaction_rules_version", max_len=64)
    validate_created_at_utc_z(entry.get("created_at"))

    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    files = entry.get("files")
    if not isinstance(files, list) or not files:
        raise SchemaValidationError("files must be non-empty list (fail-closed)")

    prev = None
    for f in files:
        p = _validate_file_entry(f)
        if prev is not None and p < prev:
            raise SchemaValidationError("files must be sorted by path (fail-closed)")
        prev = p

    expected_id = sha256_hex_of_obj(entry, drop_keys={"created_at", "delivery_pack_id"})
    if entry.get("delivery_pack_id") != expected_id:
        raise SchemaValidationError("delivery_pack_id does not match canonical hash surface (fail-closed)")
