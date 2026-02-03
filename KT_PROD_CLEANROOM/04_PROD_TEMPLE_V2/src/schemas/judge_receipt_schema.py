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


JUDGE_RECEIPT_SCHEMA_ID = "kt.judge_receipt.v1"
JUDGE_RECEIPT_SCHEMA_FILE = "fl3/kt.judge_receipt.v1.json"
JUDGE_RECEIPT_SCHEMA_VERSION_HASH = schema_version_hash(JUDGE_RECEIPT_SCHEMA_FILE)

_REQ_ORDER = (
    "schema_id",
    "schema_version_hash",
    "receipt_id",
    "work_order_id",
    "verdict",
    "reasons",
    "advisories",
    "checks",
    "created_at",
)
_REQ: Set[str] = set(_REQ_ORDER)
_ALLOWED: Set[str] = set(_REQ_ORDER)


def validate_judge_receipt(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="judge receipt")
    enforce_max_fields(entry, max_fields=64)
    require_keys(entry, required=_REQ)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    enforce_max_canonical_json_bytes(entry, max_bytes=128 * 1024)

    if entry.get("schema_id") != JUDGE_RECEIPT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != JUDGE_RECEIPT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "receipt_id")
    validate_hex_64(entry, "work_order_id")
    validate_short_string(entry, "created_at", max_len=64)

    verdict = entry.get("verdict")
    if verdict not in {"PASS", "FAIL", "FAIL_CLOSED"}:
        raise SchemaValidationError("verdict must be PASS, FAIL, or FAIL_CLOSED (fail-closed)")

    for field in ("reasons", "advisories"):
        v = entry.get(field)
        if not isinstance(v, list) or not all(isinstance(x, str) and x.strip() for x in v):
            raise SchemaValidationError(f"{field} must be a list of non-empty strings (fail-closed)")

    checks = entry.get("checks")
    if not isinstance(checks, dict):
        raise SchemaValidationError("checks must be object (fail-closed)")

