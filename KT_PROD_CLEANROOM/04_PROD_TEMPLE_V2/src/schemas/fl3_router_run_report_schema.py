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
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_ROUTER_RUN_REPORT_SCHEMA_ID = "kt.router_run_report.v1"
FL3_ROUTER_RUN_REPORT_SCHEMA_FILE = "fl3/kt.router_run_report.v1.json"
FL3_ROUTER_RUN_REPORT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_ROUTER_RUN_REPORT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "router_run_report_id",
    "run_id",
    "router_policy_id",
    "router_demo_suite_id",
    "status",
    "case_receipts",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {"notes"}
_HASH_DROP_KEYS = {"created_at", "router_run_report_id"}

_ROW_REQUIRED = {"case_id", "receipt_path", "receipt_sha256"}
_ROW_ALLOWED = set(_ROW_REQUIRED)


def _validate_case_receipt(row: Dict[str, Any]) -> Dict[str, Any]:
    enforce_max_fields(row, max_fields=8)
    require_keys(row, required=_ROW_REQUIRED)
    reject_unknown_keys(row, allowed=_ROW_ALLOWED)

    cid = str(row.get("case_id", "")).strip()
    if not cid:
        raise SchemaValidationError("case_id must be non-empty (fail-closed)")
    validate_short_string({"case_id": cid}, "case_id", max_len=64)
    row["case_id"] = cid

    p = str(row.get("receipt_path", "")).replace("\\", "/").strip()
    if not p:
        raise SchemaValidationError("receipt_path must be non-empty (fail-closed)")
    validate_short_string({"receipt_path": p}, "receipt_path", max_len=512)
    row["receipt_path"] = p

    sha = str(row.get("receipt_sha256", "")).strip()
    validate_hex_64({"receipt_sha256": sha}, "receipt_sha256")
    row["receipt_sha256"] = sha
    return row


def validate_fl3_router_run_report(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="router_run_report")
    enforce_max_fields(entry, max_fields=128)
    enforce_max_canonical_json_bytes(entry, max_bytes=512_000)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_ROUTER_RUN_REPORT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_ROUTER_RUN_REPORT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "router_run_report_id")
    validate_short_string(entry, "run_id", max_len=128)
    validate_hex_64(entry, "router_policy_id")
    validate_hex_64(entry, "router_demo_suite_id")

    status = str(entry.get("status", "")).strip().upper()
    if status not in {"PASS", "FAIL"}:
        raise SchemaValidationError("status invalid (fail-closed)")
    entry["status"] = status

    rows_val = entry.get("case_receipts")
    if not isinstance(rows_val, list) or not rows_val:
        raise SchemaValidationError("case_receipts must be non-empty list (fail-closed)")

    rows: List[Dict[str, Any]] = []
    order: List[str] = []
    seen: Set[str] = set()
    for item in rows_val:
        row = require_dict(item, name="case_receipts[]")
        row = _validate_case_receipt(row)
        cid = str(row["case_id"])
        if cid in seen:
            raise SchemaValidationError("duplicate case_id in case_receipts (fail-closed)")
        seen.add(cid)
        rows.append(row)
        order.append(cid)
    if order != sorted(order):
        raise SchemaValidationError("case_receipts must be sorted by case_id (fail-closed)")
    entry["case_receipts"] = rows

    validate_created_at_utc_z(entry.get("created_at"))
    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("router_run_report_id") != expected:
        raise SchemaValidationError("router_run_report_id does not match canonical hash surface (fail-closed)")

