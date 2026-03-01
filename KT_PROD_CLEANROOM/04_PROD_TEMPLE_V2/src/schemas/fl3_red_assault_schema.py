from __future__ import annotations

from typing import Any, Dict, List, Set

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


FL3_RED_ASSAULT_SCHEMA_ID = "kt.fl3.red_assault.v1"
FL3_RED_ASSAULT_SCHEMA_FILE = "fl3/kt.fl3.red_assault.v1.json"
FL3_RED_ASSAULT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_RED_ASSAULT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "red_assault_id",
    "results",
    "all_passed",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {"notes"}
_HASH_DROP_KEYS = {"created_at", "red_assault_id"}

_RESULT_REQUIRED = {"attack_id", "expected_exit_codes", "observed_exit_code", "passed"}
_RESULT_ALLOWED = set(_RESULT_REQUIRED)


def _validate_result(row: Dict[str, Any]) -> Dict[str, Any]:
    enforce_max_fields(row, max_fields=16)
    require_keys(row, required=_RESULT_REQUIRED)
    reject_unknown_keys(row, allowed=_RESULT_ALLOWED)
    validate_bounded_json_value(row, max_depth=4, max_string_len=256, max_list_len=64)

    attack_id = str(row.get("attack_id", "")).strip()
    if not attack_id:
        raise SchemaValidationError("attack_id must be non-empty (fail-closed)")
    validate_short_string({"attack_id": attack_id}, "attack_id", max_len=128)
    row["attack_id"] = attack_id

    expected = row.get("expected_exit_codes")
    if not isinstance(expected, list) or not expected:
        raise SchemaValidationError("expected_exit_codes must be non-empty list (fail-closed)")
    if not all(isinstance(x, int) for x in expected):
        raise SchemaValidationError("expected_exit_codes must contain integers (fail-closed)")
    row["expected_exit_codes"] = [int(x) for x in expected]

    obs = row.get("observed_exit_code")
    if not isinstance(obs, int):
        raise SchemaValidationError("observed_exit_code must be integer (fail-closed)")
    row["observed_exit_code"] = int(obs)

    passed = row.get("passed")
    if not isinstance(passed, bool):
        raise SchemaValidationError("passed must be boolean (fail-closed)")
    row["passed"] = bool(passed)
    return row


def validate_fl3_red_assault(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="fl3_red_assault")
    enforce_max_fields(entry, max_fields=128)
    enforce_max_canonical_json_bytes(entry, max_bytes=256_000)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_RED_ASSAULT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_RED_ASSAULT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "red_assault_id")

    rows_val = entry.get("results")
    if not isinstance(rows_val, list) or not rows_val:
        raise SchemaValidationError("results must be non-empty list (fail-closed)")

    rows: List[Dict[str, Any]] = []
    order: List[str] = []
    seen: Set[str] = set()
    all_passed = True
    for item in rows_val:
        row = require_dict(item, name="results[]")
        row = _validate_result(row)
        aid = str(row["attack_id"])
        if aid in seen:
            raise SchemaValidationError("duplicate attack_id (fail-closed)")
        seen.add(aid)
        rows.append(row)
        order.append(aid)
        all_passed = all_passed and bool(row.get("passed", False))
    if order != sorted(order):
        raise SchemaValidationError("results must be sorted by attack_id (fail-closed)")
    entry["results"] = rows

    ap = entry.get("all_passed")
    if not isinstance(ap, bool):
        raise SchemaValidationError("all_passed must be boolean (fail-closed)")
    if bool(ap) != bool(all_passed):
        raise SchemaValidationError("all_passed mismatch vs results (fail-closed)")
    entry["all_passed"] = bool(ap)

    validate_created_at_utc_z(entry.get("created_at"))
    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("red_assault_id") != expected:
        raise SchemaValidationError("red_assault_id does not match canonical hash surface (fail-closed)")

