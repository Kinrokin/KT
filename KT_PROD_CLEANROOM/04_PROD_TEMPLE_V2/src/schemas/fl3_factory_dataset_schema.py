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


FL3_FACTORY_DATASET_SCHEMA_ID = "kt.factory.dataset.v1"
FL3_FACTORY_DATASET_SCHEMA_FILE = "fl3/kt.factory.dataset.v1.json"
FL3_FACTORY_DATASET_SCHEMA_VERSION_HASH = schema_version_hash(FL3_FACTORY_DATASET_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "dataset_id",
    "job_id",
    "rows",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "dataset_id"}


def validate_fl3_factory_dataset(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 factory dataset")
    enforce_max_fields(entry, max_fields=16)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    enforce_max_canonical_json_bytes(entry, max_bytes=2 * 1024 * 1024)

    if entry.get("schema_id") != FL3_FACTORY_DATASET_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_FACTORY_DATASET_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "dataset_id")
    validate_hex_64(entry, "job_id")
    validate_created_at_utc_z(entry.get("created_at"))

    rows = entry.get("rows")
    if not isinstance(rows, list) or not rows:
        raise SchemaValidationError("rows must be a non-empty list (fail-closed)")
    validate_bounded_json_value(rows, max_depth=8, max_string_len=8192, max_list_len=20000)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("dataset_id") != expected:
        raise SchemaValidationError("dataset_id does not match canonical hash surface (fail-closed)")

