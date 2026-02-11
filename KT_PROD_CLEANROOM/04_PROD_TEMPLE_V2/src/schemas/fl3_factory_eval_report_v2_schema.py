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


FL3_FACTORY_EVAL_REPORT_V2_SCHEMA_ID = "kt.factory.eval_report.v2"
FL3_FACTORY_EVAL_REPORT_V2_SCHEMA_FILE = "fl3/kt.factory.eval_report.v2.json"
FL3_FACTORY_EVAL_REPORT_V2_SCHEMA_VERSION_HASH = schema_version_hash(FL3_FACTORY_EVAL_REPORT_V2_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "eval_id",
    "job_id",
    "adapter_id",
    "adapter_version",
    "battery_id",
    "utility_pack_id",
    "utility_pack_hash",
    "utility_floor_score",
    "utility_floor_pass",
    "metric_bindings",
    "metric_probes",
    "probe_policy",
    "results",
    "final_verdict",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "eval_id"}


def validate_fl3_factory_eval_report_v2(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL4 factory eval report v2")
    enforce_max_fields(entry, max_fields=48)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    enforce_max_canonical_json_bytes(entry, max_bytes=512 * 1024)

    if entry.get("schema_id") != FL3_FACTORY_EVAL_REPORT_V2_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_FACTORY_EVAL_REPORT_V2_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "eval_id")
    validate_hex_64(entry, "job_id")
    validate_short_string(entry, "adapter_id", max_len=128)
    validate_short_string(entry, "adapter_version", max_len=64)
    validate_short_string(entry, "battery_id", max_len=128)
    validate_short_string(entry, "utility_pack_id", max_len=128)
    validate_hex_64(entry, "utility_pack_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    try:
        score = float(entry.get("utility_floor_score"))
    except Exception as exc:
        raise SchemaValidationError("utility_floor_score must be number (fail-closed)") from exc
    if score < 0.0 or score > 1.0:
        raise SchemaValidationError("utility_floor_score must be in [0,1] (fail-closed)")
    if not isinstance(entry.get("utility_floor_pass"), bool):
        raise SchemaValidationError("utility_floor_pass must be boolean (fail-closed)")

    final = entry.get("final_verdict")
    if final not in {"PASS", "FAIL"}:
        raise SchemaValidationError("final_verdict must be PASS or FAIL (fail-closed)")

    for list_key in ("metric_bindings", "metric_probes"):
        value = entry.get(list_key)
        if not isinstance(value, list) or len(value) < 1:
            raise SchemaValidationError(f"{list_key} must be non-empty list (fail-closed)")
    for b in entry["metric_bindings"]:
        bd = require_dict(b, name="metric_binding")
        if set(bd.keys()) != {"metric_id", "metric_version_hash", "metric_schema_hash", "metric_impl_hash"}:
            raise SchemaValidationError("metric_binding keys mismatch (fail-closed)")
        validate_short_string(bd, "metric_id", max_len=128)
        validate_hex_64(bd, "metric_version_hash")
        validate_hex_64(bd, "metric_schema_hash")
        validate_hex_64(bd, "metric_impl_hash")
    for p in entry["metric_probes"]:
        pd = require_dict(p, name="metric_probe")
        if set(pd.keys()) != {"metric_id", "metric_impl_hash", "delta", "agreement"}:
            raise SchemaValidationError("metric_probe keys mismatch (fail-closed)")
        validate_short_string(pd, "metric_id", max_len=128)
        validate_hex_64(pd, "metric_impl_hash")
        if not isinstance(pd.get("agreement"), bool):
            raise SchemaValidationError("metric_probe agreement must be boolean (fail-closed)")
        try:
            float(pd.get("delta"))
        except Exception as exc:
            raise SchemaValidationError("metric_probe delta must be number (fail-closed)") from exc

    probe_policy = require_dict(entry.get("probe_policy"), name="probe_policy")
    if set(probe_policy.keys()) != {"tolerance", "fail_on_disagreement"}:
        raise SchemaValidationError("probe_policy keys mismatch (fail-closed)")
    try:
        tol = float(probe_policy.get("tolerance"))
    except Exception as exc:
        raise SchemaValidationError("probe_policy tolerance must be number (fail-closed)") from exc
    if tol < 0.0:
        raise SchemaValidationError("probe_policy tolerance must be >=0 (fail-closed)")
    if not isinstance(probe_policy.get("fail_on_disagreement"), bool):
        raise SchemaValidationError("probe_policy fail_on_disagreement must be boolean (fail-closed)")

    results = entry.get("results")
    if not isinstance(results, dict):
        raise SchemaValidationError("results must be an object (fail-closed)")
    validate_bounded_json_value(results, max_depth=10, max_string_len=4096, max_list_len=4096)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("eval_id") != expected:
        raise SchemaValidationError("eval_id does not match canonical hash surface (fail-closed)")

