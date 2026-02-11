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
    validate_short_string,
)
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_FACTORY_EVAL_REPORT_SCHEMA_ID = "kt.factory.eval_report.v1"
FL3_FACTORY_EVAL_REPORT_SCHEMA_FILE = "fl3/kt.factory.eval_report.v1.json"
FL3_FACTORY_EVAL_REPORT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_FACTORY_EVAL_REPORT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "eval_id",
    "job_id",
    "adapter_id",
    "adapter_version",
    "battery_id",
    "results",
    "final_verdict",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "eval_id"}


def validate_fl3_factory_eval_report(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 factory eval report")
    enforce_max_fields(entry, max_fields=32)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    enforce_max_canonical_json_bytes(entry, max_bytes=512 * 1024)

    if entry.get("schema_id") != FL3_FACTORY_EVAL_REPORT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_FACTORY_EVAL_REPORT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "eval_id")
    validate_hex_64(entry, "job_id")
    validate_short_string(entry, "adapter_id", max_len=128)
    validate_short_string(entry, "adapter_version", max_len=64)
    validate_short_string(entry, "battery_id", max_len=128)
    validate_created_at_utc_z(entry.get("created_at"))

    final = entry.get("final_verdict")
    if final not in {"PASS", "FAIL"}:
        raise SchemaValidationError("final_verdict must be PASS or FAIL (fail-closed)")

    results = entry.get("results")
    if not isinstance(results, dict):
        raise SchemaValidationError("results must be an object (fail-closed)")
    validate_bounded_json_value(results, max_depth=8, max_string_len=4096, max_list_len=4096)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("eval_id") != expected:
        raise SchemaValidationError("eval_id does not match canonical hash surface (fail-closed)")

