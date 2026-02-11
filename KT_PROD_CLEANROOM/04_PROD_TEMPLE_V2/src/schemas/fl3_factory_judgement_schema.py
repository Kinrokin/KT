from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64, validate_short_string
from schemas.fl3_schema_common import ensure_sorted_str_list, sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_FACTORY_JUDGEMENT_SCHEMA_ID = "kt.factory.judgement.v1"
FL3_FACTORY_JUDGEMENT_SCHEMA_FILE = "fl3/kt.factory.judgement.v1.json"
FL3_FACTORY_JUDGEMENT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_FACTORY_JUDGEMENT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "judgement_id",
    "job_id",
    "dataset_id",
    "accepted_row_ids",
    "rejected_row_ids",
    "judge_ref",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "judgement_id"}


def validate_fl3_factory_judgement(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 factory judgement")
    enforce_max_fields(entry, max_fields=24)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_FACTORY_JUDGEMENT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_FACTORY_JUDGEMENT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "judgement_id")
    validate_hex_64(entry, "job_id")
    validate_hex_64(entry, "dataset_id")
    validate_created_at_utc_z(entry.get("created_at"))
    validate_short_string(entry, "judge_ref", max_len=128)

    _ = ensure_sorted_str_list(entry.get("accepted_row_ids"), field="accepted_row_ids")
    _ = ensure_sorted_str_list(entry.get("rejected_row_ids"), field="rejected_row_ids")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("judgement_id") != expected:
        raise SchemaValidationError("judgement_id does not match canonical hash surface (fail-closed)")

