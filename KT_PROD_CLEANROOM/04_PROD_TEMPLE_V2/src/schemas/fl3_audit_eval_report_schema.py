from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

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


FL3_AUDIT_EVAL_REPORT_SCHEMA_ID = "kt.audit_eval_report.v1"
FL3_AUDIT_EVAL_REPORT_SCHEMA_FILE = "fl3/kt.audit_eval_report.v1.json"
FL3_AUDIT_EVAL_REPORT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_AUDIT_EVAL_REPORT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "audit_eval_report_id",
    "run_id",
    "law_bundle_hash",
    "suite_registry_id",
    "canonical_lane",
    "attestation_mode",
    "decision",
    "axis_scores",
    "artifacts",
    "one_line_verdict",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {"notes"}
_HASH_DROP_KEYS = {"created_at", "audit_eval_report_id"}


def validate_fl3_audit_eval_report(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="audit_eval_report")
    enforce_max_fields(entry, max_fields=256)
    enforce_max_canonical_json_bytes(entry, max_bytes=512_000)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_AUDIT_EVAL_REPORT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_AUDIT_EVAL_REPORT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "audit_eval_report_id")
    validate_short_string(entry, "run_id", max_len=128)
    validate_hex_64(entry, "law_bundle_hash")
    validate_hex_64(entry, "suite_registry_id")

    canon = entry.get("canonical_lane")
    if not isinstance(canon, bool):
        raise SchemaValidationError("canonical_lane must be boolean (fail-closed)")
    entry["canonical_lane"] = bool(canon)

    mode = str(entry.get("attestation_mode", "")).strip().upper()
    if mode not in {"SIMULATED", "HMAC", "PKI"}:
        raise SchemaValidationError("attestation_mode invalid (fail-closed)")
    entry["attestation_mode"] = mode

    decision = str(entry.get("decision", "")).strip().upper()
    if decision not in {"PROMOTE", "HOLD", "QUARANTINE"}:
        raise SchemaValidationError("decision invalid (fail-closed)")
    entry["decision"] = decision

    axis_scores = require_dict(entry.get("axis_scores"), name="axis_scores")
    enforce_max_fields(axis_scores, max_fields=64)
    validate_bounded_json_value(axis_scores, max_depth=2, max_string_len=64, max_list_len=0)
    for k, v in axis_scores.items():
        axis_id = str(k).strip()
        if not axis_id:
            raise SchemaValidationError("axis_scores contains empty axis id (fail-closed)")
        validate_short_string({"axis_id": axis_id}, "axis_id", max_len=64)
        if not isinstance(v, (int, float)):
            raise SchemaValidationError("axis_scores values must be numbers (fail-closed)")
        f = float(v)
        if f < 0.0 or f > 1.0:
            raise SchemaValidationError("axis_scores values must be in [0,1] (fail-closed)")
        axis_scores[axis_id] = f
    entry["axis_scores"] = {k: axis_scores[k] for k in sorted(axis_scores.keys())}

    artifacts_val = entry.get("artifacts")
    if not isinstance(artifacts_val, list) or not artifacts_val:
        raise SchemaValidationError("artifacts must be non-empty list (fail-closed)")
    out: List[Dict[str, Any]] = []
    order: List[Tuple[str, str]] = []
    seen: Set[str] = set()
    for item in artifacts_val:
        row = require_dict(item, name="artifacts[]")
        enforce_max_fields(row, max_fields=4)
        require_keys(row, required={"path", "sha256"})
        reject_unknown_keys(row, allowed={"path", "sha256"})
        p = str(row.get("path", "")).replace("\\", "/").strip()
        if not p:
            raise SchemaValidationError("artifacts[].path must be non-empty (fail-closed)")
        validate_short_string({"path": p}, "path", max_len=512)
        sha = str(row.get("sha256", "")).strip()
        validate_hex_64({"sha256": sha}, "sha256")
        if p in seen:
            raise SchemaValidationError("duplicate artifacts[].path (fail-closed)")
        seen.add(p)
        out.append({"path": p, "sha256": sha})
        order.append((p, sha))
    if [x[0] for x in order] != sorted([x[0] for x in order]):
        raise SchemaValidationError("artifacts must be sorted by path (fail-closed)")
    entry["artifacts"] = out

    olv = str(entry.get("one_line_verdict", "")).strip()
    if not olv:
        raise SchemaValidationError("one_line_verdict must be non-empty (fail-closed)")
    validate_short_string({"one_line_verdict": olv}, "one_line_verdict", max_len=4096)
    entry["one_line_verdict"] = olv

    validate_created_at_utc_z(entry.get("created_at"))
    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("audit_eval_report_id") != expected:
        raise SchemaValidationError("audit_eval_report_id does not match canonical hash surface (fail-closed)")

