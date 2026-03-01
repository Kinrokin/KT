from __future__ import annotations

from typing import Any, Dict, List, Set

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


FL3_ROUTING_RECEIPT_SCHEMA_ID = "kt.routing_receipt.v1"
FL3_ROUTING_RECEIPT_SCHEMA_FILE = "fl3/kt.routing_receipt.v1.json"
FL3_ROUTING_RECEIPT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_ROUTING_RECEIPT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "routing_receipt_id",
    "run_id",
    "router_policy_id",
    "router_demo_suite_id",
    "case_id",
    "input_sha256",
    "domain_tag",
    "matched_keywords",
    "selected_adapter_ids",
    "required_adapter_ids",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {"notes"}
_HASH_DROP_KEYS = {"created_at", "routing_receipt_id"}


def validate_fl3_routing_receipt(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="routing_receipt")
    enforce_max_fields(entry, max_fields=64)
    enforce_max_canonical_json_bytes(entry, max_bytes=128_000)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_ROUTING_RECEIPT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_ROUTING_RECEIPT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "routing_receipt_id")
    validate_short_string(entry, "run_id", max_len=128)
    validate_hex_64(entry, "router_policy_id")
    validate_hex_64(entry, "router_demo_suite_id")
    validate_short_string(entry, "case_id", max_len=64)
    validate_hex_64(entry, "input_sha256")
    validate_short_string(entry, "domain_tag", max_len=128)

    entry["matched_keywords"] = ensure_sorted_str_list(entry.get("matched_keywords"), field="matched_keywords")
    entry["selected_adapter_ids"] = ensure_sorted_str_list(entry.get("selected_adapter_ids"), field="selected_adapter_ids")
    if not entry["selected_adapter_ids"]:
        raise SchemaValidationError("selected_adapter_ids must be non-empty (fail-closed)")
    entry["required_adapter_ids"] = ensure_sorted_str_list(entry.get("required_adapter_ids"), field="required_adapter_ids")

    required = set(entry["required_adapter_ids"])
    selected = set(entry["selected_adapter_ids"])
    if not required.issubset(selected):
        raise SchemaValidationError("required_adapter_ids must be subset of selected_adapter_ids (fail-closed)")

    validate_created_at_utc_z(entry.get("created_at"))
    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("routing_receipt_id") != expected:
        raise SchemaValidationError("routing_receipt_id does not match canonical hash surface (fail-closed)")

