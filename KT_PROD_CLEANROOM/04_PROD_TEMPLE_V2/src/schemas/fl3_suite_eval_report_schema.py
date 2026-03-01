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


FL3_SUITE_EVAL_REPORT_SCHEMA_ID = "kt.suite_eval_report.v1"
FL3_SUITE_EVAL_REPORT_SCHEMA_FILE = "fl3/kt.suite_eval_report.v1.json"
FL3_SUITE_EVAL_REPORT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_SUITE_EVAL_REPORT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "suite_eval_report_id",
    "suite_outputs_id",
    "suite_definition_id",
    "validator_catalog_id",
    "axis_scoring_policy_id",
    "status",
    "case_results",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {"notes"}
_HASH_DROP_KEYS = {"created_at", "suite_eval_report_id"}

_CASE_REQUIRED = {"case_id", "passed", "validator_results"}
_CASE_ALLOWED = set(_CASE_REQUIRED) | {"failed_validator_ids", "notes"}

_VR_REQUIRED = {"validator_id", "passed", "score"}
_VR_ALLOWED = set(_VR_REQUIRED) | {"notes"}


def validate_fl3_suite_eval_report(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="suite_eval_report")
    enforce_max_fields(entry, max_fields=256)
    enforce_max_canonical_json_bytes(entry, max_bytes=4_000_000)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_SUITE_EVAL_REPORT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_SUITE_EVAL_REPORT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    for f in (
        "suite_eval_report_id",
        "suite_outputs_id",
        "suite_definition_id",
        "validator_catalog_id",
        "axis_scoring_policy_id",
    ):
        validate_hex_64(entry, f)

    st = str(entry.get("status", "")).strip().upper()
    if st not in {"PASS", "FAIL"}:
        raise SchemaValidationError("status invalid (fail-closed)")
    entry["status"] = st

    validate_created_at_utc_z(entry.get("created_at"))
    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    cases_val = entry.get("case_results")
    if not isinstance(cases_val, list) or not cases_val:
        raise SchemaValidationError("case_results must be non-empty list (fail-closed)")

    out_cases: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    order: List[str] = []
    for item in cases_val:
        row = require_dict(item, name="case_results[]")
        enforce_max_fields(row, max_fields=64)
        require_keys(row, required=_CASE_REQUIRED)
        reject_unknown_keys(row, allowed=_CASE_ALLOWED)
        cid = str(row.get("case_id", "")).strip()
        if not cid:
            raise SchemaValidationError("case_id must be non-empty (fail-closed)")
        validate_short_string({"case_id": cid}, "case_id", max_len=64)
        if cid in seen:
            raise SchemaValidationError("duplicate case_id (fail-closed)")
        seen.add(cid)
        order.append(cid)

        passed = row.get("passed")
        if not isinstance(passed, bool):
            raise SchemaValidationError("passed must be boolean (fail-closed)")

        vrs_val = row.get("validator_results")
        if not isinstance(vrs_val, list) or not vrs_val:
            raise SchemaValidationError("validator_results must be non-empty list (fail-closed)")
        out_vrs: List[Dict[str, Any]] = []
        seen_vid: Set[str] = set()
        vid_order: List[str] = []
        failed: List[str] = []
        for vr in vrs_val:
            vrd = require_dict(vr, name="validator_results[]")
            enforce_max_fields(vrd, max_fields=8)
            require_keys(vrd, required=_VR_REQUIRED)
            reject_unknown_keys(vrd, allowed=_VR_ALLOWED)
            vid = str(vrd.get("validator_id", "")).strip()
            if not vid:
                raise SchemaValidationError("validator_id must be non-empty (fail-closed)")
            validate_short_string({"validator_id": vid}, "validator_id", max_len=128)
            if vid in seen_vid:
                raise SchemaValidationError("duplicate validator_id in case (fail-closed)")
            seen_vid.add(vid)
            vid_order.append(vid)
            vp = vrd.get("passed")
            if not isinstance(vp, bool):
                raise SchemaValidationError("validator passed must be boolean (fail-closed)")
            sc = vrd.get("score")
            if not isinstance(sc, (int, float)):
                raise SchemaValidationError("validator score must be number (fail-closed)")
            sf = float(sc)
            if sf < 0.0 or sf > 1.0:
                raise SchemaValidationError("validator score must be in [0,1] (fail-closed)")
            notes = vrd.get("notes", None)
            if notes is not None:
                if not isinstance(notes, str):
                    raise SchemaValidationError("validator notes must be string or null (fail-closed)")
                validate_short_string({"notes": notes}, "notes", max_len=2048)
            out_vrs.append({"validator_id": vid, "passed": bool(vp), "score": sf, "notes": notes})
            if not vp:
                failed.append(vid)
        if vid_order != sorted(vid_order):
            raise SchemaValidationError("validator_results must be sorted by validator_id (fail-closed)")

        failed_sorted = sorted(failed)
        if "failed_validator_ids" in row and row["failed_validator_ids"] is not None:
            fv = row.get("failed_validator_ids")
            if not isinstance(fv, list) or not all(isinstance(x, str) and x.strip() for x in fv):
                raise SchemaValidationError("failed_validator_ids must be list[str] (fail-closed)")
            fv_norm = [x.strip() for x in fv]
            if fv_norm != failed_sorted:
                raise SchemaValidationError("failed_validator_ids mismatch vs validator_results (fail-closed)")
        row["failed_validator_ids"] = failed_sorted

        if passed and failed_sorted:
            raise SchemaValidationError("case marked passed but has failed validators (fail-closed)")
        if (not passed) and (not failed_sorted):
            raise SchemaValidationError("case marked failed but no failed validators (fail-closed)")

        row["validator_results"] = out_vrs
        if "notes" in row and row["notes"] is not None:
            validate_short_string(row, "notes", max_len=2048)
        out_cases.append(row)

    if order != sorted(order):
        raise SchemaValidationError("case_results must be sorted by case_id (fail-closed)")
    entry["case_results"] = out_cases

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("suite_eval_report_id") != expected:
        raise SchemaValidationError("suite_eval_report_id does not match canonical hash surface (fail-closed)")

