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


FL3_ROUTER_DEMO_SUITE_SCHEMA_ID = "kt.router_demo_suite.v1"
FL3_ROUTER_DEMO_SUITE_SCHEMA_FILE = "fl3/kt.router_demo_suite.v1.json"
FL3_ROUTER_DEMO_SUITE_SCHEMA_VERSION_HASH = schema_version_hash(FL3_ROUTER_DEMO_SUITE_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "router_demo_suite_id",
    "suite_id",
    "suite_version",
    "purpose",
    "cases",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {"notes"}
_HASH_DROP_KEYS = {"created_at", "router_demo_suite_id"}

_CASE_REQUIRED = {"case_id", "input_text", "expected_domain_tag", "expected_adapter_ids"}
_CASE_ALLOWED = set(_CASE_REQUIRED) | {"notes"}


def _validate_case(row: Dict[str, Any]) -> Dict[str, Any]:
    enforce_max_fields(row, max_fields=16)
    require_keys(row, required=_CASE_REQUIRED)
    reject_unknown_keys(row, allowed=_CASE_ALLOWED)

    cid = str(row.get("case_id", "")).strip()
    if not cid:
        raise SchemaValidationError("case_id must be non-empty (fail-closed)")
    validate_short_string({"case_id": cid}, "case_id", max_len=64)
    row["case_id"] = cid

    txt = str(row.get("input_text", "")).strip()
    if not txt:
        raise SchemaValidationError("input_text must be non-empty (fail-closed)")
    validate_short_string({"input_text": txt}, "input_text", max_len=4000)
    row["input_text"] = txt

    dom = str(row.get("expected_domain_tag", "")).strip()
    if not dom:
        raise SchemaValidationError("expected_domain_tag must be non-empty (fail-closed)")
    validate_short_string({"expected_domain_tag": dom}, "expected_domain_tag", max_len=128)
    row["expected_domain_tag"] = dom

    exp = ensure_sorted_str_list(row.get("expected_adapter_ids"), field="expected_adapter_ids")
    if not exp:
        raise SchemaValidationError("expected_adapter_ids must be non-empty list (fail-closed)")
    row["expected_adapter_ids"] = exp

    if "notes" in row and row["notes"] is not None:
        validate_short_string(row, "notes", max_len=2048)
    return row


def validate_fl3_router_demo_suite(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="router_demo_suite")
    enforce_max_fields(entry, max_fields=96)
    enforce_max_canonical_json_bytes(entry, max_bytes=512_000)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_ROUTER_DEMO_SUITE_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_ROUTER_DEMO_SUITE_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "router_demo_suite_id")
    validate_short_string(entry, "suite_id", max_len=128)
    validate_short_string(entry, "suite_version", max_len=64)
    validate_short_string(entry, "purpose", max_len=2000)

    validate_created_at_utc_z(entry.get("created_at"))
    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    cases_val = entry.get("cases")
    if not isinstance(cases_val, list) or not cases_val:
        raise SchemaValidationError("cases must be non-empty list (fail-closed)")

    cases: List[Dict[str, Any]] = []
    order: List[str] = []
    seen: Set[str] = set()
    for item in cases_val:
        row = require_dict(item, name="cases[]")
        row = _validate_case(row)
        cid = str(row["case_id"])
        if cid in seen:
            raise SchemaValidationError("duplicate case_id (fail-closed)")
        seen.add(cid)
        cases.append(row)
        order.append(cid)
    if order != sorted(order):
        raise SchemaValidationError("cases must be sorted by case_id (fail-closed)")
    entry["cases"] = cases

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("router_demo_suite_id") != expected:
        raise SchemaValidationError("router_demo_suite_id does not match canonical hash surface (fail-closed)")

