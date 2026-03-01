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
from schemas.fl3_schema_common import ensure_sorted_str_list, sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_EVALUATION_ADMISSION_RECEIPT_SCHEMA_ID = "kt.evaluation_admission_receipt.v1"
FL3_EVALUATION_ADMISSION_RECEIPT_SCHEMA_FILE = "fl3/kt.evaluation_admission_receipt.v1.json"
FL3_EVALUATION_ADMISSION_RECEIPT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_EVALUATION_ADMISSION_RECEIPT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "admission_receipt_id",
    "lane_id",
    "decision",
    "reason_codes",
    "evaluation_plan_ref",
    "evaluation_plan_sha256",
    "base_model_id",
    "suite_id",
    "suite_root_hash",
    "decode_policy_id",
    "decode_cfg_hash",
    "suite_registry_ref",
    "suite_registry_sha256",
    "counterpressure_plan_ref",
    "counterpressure_plan_sha256",
    "break_hypothesis_ref",
    "break_hypothesis_sha256",
    "law_bundle_hash",
    "failure_taxonomy_id",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {"notes"}
_HASH_DROP_KEYS = {"created_at", "admission_receipt_id"}


def validate_fl3_evaluation_admission_receipt(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 evaluation admission receipt v1")
    enforce_max_fields(entry, max_fields=80)
    enforce_max_canonical_json_bytes(entry, max_bytes=128_000)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_EVALUATION_ADMISSION_RECEIPT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_EVALUATION_ADMISSION_RECEIPT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "admission_receipt_id")
    validate_short_string(entry, "lane_id", max_len=64)
    validate_created_at_utc_z(entry.get("created_at"))

    decision = str(entry.get("decision", "")).strip().upper()
    if decision not in {"PASS", "FAIL_CLOSED"}:
        raise SchemaValidationError("decision invalid (fail-closed)")
    entry["decision"] = decision

    entry["reason_codes"] = ensure_sorted_str_list(entry.get("reason_codes"), field="reason_codes")

    # Immutable input binding
    validate_short_string(entry, "evaluation_plan_ref", max_len=512)
    validate_hex_64(entry, "evaluation_plan_sha256")
    validate_short_string(entry, "base_model_id", max_len=128)
    validate_short_string(entry, "suite_id", max_len=128)
    validate_hex_64(entry, "suite_root_hash")
    validate_short_string(entry, "decode_policy_id", max_len=128)
    validate_hex_64(entry, "decode_cfg_hash")

    validate_short_string(entry, "suite_registry_ref", max_len=512)
    validate_hex_64(entry, "suite_registry_sha256")
    validate_short_string(entry, "counterpressure_plan_ref", max_len=512)
    validate_hex_64(entry, "counterpressure_plan_sha256")
    validate_short_string(entry, "break_hypothesis_ref", max_len=512)
    validate_hex_64(entry, "break_hypothesis_sha256")
    validate_hex_64(entry, "law_bundle_hash")
    validate_hex_64(entry, "failure_taxonomy_id")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("admission_receipt_id") != expected:
        raise SchemaValidationError("admission_receipt_id does not match canonical hash surface (fail-closed)")

