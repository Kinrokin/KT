from __future__ import annotations

from typing import Any, Dict, List, Set

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


FL3_FAILURE_TAXONOMY_SCHEMA_ID = "kt.failure_taxonomy.v1"
FL3_FAILURE_TAXONOMY_SCHEMA_FILE = "fl3/kt.failure_taxonomy.v1.json"
FL3_FAILURE_TAXONOMY_SCHEMA_VERSION_HASH = schema_version_hash(FL3_FAILURE_TAXONOMY_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "taxonomy_id",
    "taxonomy_version",
    "categories",
    "mappings",
    "created_at",
)
_OPTIONAL_ORDER = ("notes",)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)
_HASH_DROP_KEYS = {"created_at", "taxonomy_id"}
_ALLOWED_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def _validate_categories(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise SchemaValidationError("categories must be a non-empty list (fail-closed)")
    out: List[Dict[str, Any]] = []
    for item in value:
        row = require_dict(item, name="categories[]")
        require_keys(row, required={"category_id", "title", "description"})
        reject_unknown_keys(row, allowed={"category_id", "title", "description"})
        category_id = str(row.get("category_id", "")).strip()
        title = str(row.get("title", "")).strip()
        desc = row.get("description")
        if not category_id:
            raise SchemaValidationError("categories[].category_id must be non-empty string (fail-closed)")
        if not title:
            raise SchemaValidationError("categories[].title must be non-empty string (fail-closed)")
        if desc is not None and not isinstance(desc, str):
            raise SchemaValidationError("categories[].description must be string or null (fail-closed)")
        validate_short_string({"category_id": category_id}, "category_id", max_len=64)
        validate_short_string({"title": title}, "title", max_len=128)
        if isinstance(desc, str):
            validate_short_string({"description": desc}, "description", max_len=1024)
        out.append({"category_id": category_id, "title": title, "description": desc})

    ids = [r["category_id"] for r in out]
    if ids != sorted(ids):
        raise SchemaValidationError("categories must be sorted by category_id (fail-closed)")
    if len(set(ids)) != len(ids):
        raise SchemaValidationError("categories category_id values must be unique (fail-closed)")
    return out


def _validate_mappings(value: Any, *, category_ids: Set[str]) -> List[Dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise SchemaValidationError("mappings must be a non-empty list (fail-closed)")
    out: List[Dict[str, Any]] = []
    for item in value:
        row = require_dict(item, name="mappings[]")
        require_keys(row, required={"reason_code", "category_id", "severity"})
        reject_unknown_keys(row, allowed={"reason_code", "category_id", "severity"})
        reason_code = str(row.get("reason_code", "")).strip()
        category_id = str(row.get("category_id", "")).strip()
        severity = str(row.get("severity", "")).strip().upper()
        if not reason_code:
            raise SchemaValidationError("mappings[].reason_code must be non-empty string (fail-closed)")
        if not category_id:
            raise SchemaValidationError("mappings[].category_id must be non-empty string (fail-closed)")
        if severity not in _ALLOWED_SEVERITIES:
            raise SchemaValidationError("mappings[].severity invalid (fail-closed)")
        if category_id not in category_ids:
            raise SchemaValidationError(f"mappings[].category_id unknown (fail-closed): {category_id!r}")
        validate_short_string({"reason_code": reason_code}, "reason_code", max_len=128)
        validate_short_string({"category_id": category_id}, "category_id", max_len=64)
        out.append({"reason_code": reason_code, "category_id": category_id, "severity": severity})

    codes = [r["reason_code"] for r in out]
    if codes != sorted(codes):
        raise SchemaValidationError("mappings must be sorted by reason_code (fail-closed)")
    if len(set(codes)) != len(codes):
        raise SchemaValidationError("mappings reason_code values must be unique (fail-closed)")
    return out


def validate_fl3_failure_taxonomy(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="failure_taxonomy")
    enforce_max_fields(entry, max_fields=2048)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_FAILURE_TAXONOMY_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_FAILURE_TAXONOMY_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "taxonomy_id")
    validate_created_at_utc_z(entry.get("created_at"))

    validate_short_string(entry, "taxonomy_version", max_len=64)
    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    categories = _validate_categories(entry.get("categories"))
    category_ids = {c["category_id"] for c in categories}
    _ = _validate_mappings(entry.get("mappings"), category_ids=category_ids)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("taxonomy_id") != expected:
        raise SchemaValidationError("taxonomy_id does not match canonical hash surface (fail-closed)")

