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


FL3_SUITE_DEFINITION_SCHEMA_ID = "kt.suite_definition.v1"
FL3_SUITE_DEFINITION_SCHEMA_FILE = "fl3/kt.suite_definition.v1.json"
FL3_SUITE_DEFINITION_SCHEMA_VERSION_HASH = schema_version_hash(FL3_SUITE_DEFINITION_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "suite_definition_id",
    "suite_id",
    "suite_version",
    "purpose",
    "validator_catalog_ref",
    "validator_catalog_id",
    "axis_scoring_policy_ref",
    "axis_scoring_policy_id",
    "cases",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {"notes"}
_HASH_DROP_KEYS = {"created_at", "suite_definition_id"}

_CASE_REQUIRED = {"case_id", "domain_tag", "expected_behavior", "prompt", "validator_ids"}
_CASE_ALLOWED = set(_CASE_REQUIRED) | {"tags", "notes"}


def _validate_case(row: Dict[str, Any]) -> Dict[str, Any]:
    enforce_max_fields(row, max_fields=32)
    require_keys(row, required=_CASE_REQUIRED)
    reject_unknown_keys(row, allowed=_CASE_ALLOWED)

    cid = str(row.get("case_id", "")).strip()
    if not cid:
        raise SchemaValidationError("case_id must be non-empty (fail-closed)")
    validate_short_string({"case_id": cid}, "case_id", max_len=64)
    row["case_id"] = cid

    tag = str(row.get("domain_tag", "")).strip()
    if not tag:
        raise SchemaValidationError("domain_tag must be non-empty (fail-closed)")
    validate_short_string({"domain_tag": tag}, "domain_tag", max_len=128)
    row["domain_tag"] = tag

    eb = str(row.get("expected_behavior", "")).strip().upper()
    if eb not in {"COMPLY", "REFUSE", "CLARIFY"}:
        raise SchemaValidationError("expected_behavior invalid (fail-closed)")
    row["expected_behavior"] = eb

    prompt = str(row.get("prompt", "")).strip()
    if not prompt:
        raise SchemaValidationError("prompt must be non-empty (fail-closed)")
    validate_short_string({"prompt": prompt}, "prompt", max_len=4000)
    row["prompt"] = prompt

    vids = ensure_sorted_str_list(row.get("validator_ids"), field="validator_ids")
    row["validator_ids"] = vids

    if "tags" in row and row["tags"] is not None:
        tags = ensure_sorted_str_list(row.get("tags"), field="tags")
        row["tags"] = tags
    if "notes" in row and row["notes"] is not None:
        validate_short_string(row, "notes", max_len=2048)
    return row


def validate_fl3_suite_definition(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="suite_definition")
    enforce_max_fields(entry, max_fields=128)
    enforce_max_canonical_json_bytes(entry, max_bytes=512_000)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_SUITE_DEFINITION_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_SUITE_DEFINITION_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "suite_definition_id")
    validate_short_string(entry, "suite_id", max_len=128)
    validate_short_string(entry, "suite_version", max_len=64)
    validate_short_string(entry, "purpose", max_len=2000)

    validate_short_string(entry, "validator_catalog_ref", max_len=512)
    validate_hex_64(entry, "validator_catalog_id")
    validate_short_string(entry, "axis_scoring_policy_ref", max_len=512)
    validate_hex_64(entry, "axis_scoring_policy_id")

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
    if entry.get("suite_definition_id") != expected:
        raise SchemaValidationError("suite_definition_id does not match canonical hash surface (fail-closed)")

