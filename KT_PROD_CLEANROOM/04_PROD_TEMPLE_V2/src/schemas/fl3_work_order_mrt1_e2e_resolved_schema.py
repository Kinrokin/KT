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
from schemas.schema_files import schema_version_hash


FL3_WORK_ORDER_MRT1_E2E_RESOLVED_SCHEMA_ID = "kt.work_order.mrt1_e2e.resolved.v1"
FL3_WORK_ORDER_MRT1_E2E_RESOLVED_SCHEMA_FILE = "fl3/kt.work_order.mrt1_e2e.resolved.v1.json"
FL3_WORK_ORDER_MRT1_E2E_RESOLVED_SCHEMA_VERSION_HASH = schema_version_hash(FL3_WORK_ORDER_MRT1_E2E_RESOLVED_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "run_name",
    "run_root",
    "law_bundle_hash_required",
    "env",
    "commands_executed",
    "artifacts",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)


def validate_fl3_work_order_mrt1_e2e_resolved(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="work_order.mrt1_e2e.resolved")
    enforce_max_fields(entry, max_fields=64)
    enforce_max_canonical_json_bytes(entry, max_bytes=256 * 1024)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    validate_bounded_json_value(entry, max_depth=8, max_string_len=32_768, max_list_len=2048)

    if entry.get("schema_id") != FL3_WORK_ORDER_MRT1_E2E_RESOLVED_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_WORK_ORDER_MRT1_E2E_RESOLVED_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_short_string(entry, "run_name", max_len=256)
    validate_short_string(entry, "run_root", max_len=1024)
    validate_hex_64(entry, "law_bundle_hash_required")

    env = entry.get("env")
    if not isinstance(env, dict) or not env:
        raise SchemaValidationError("env must be non-empty object (fail-closed)")
    for k, v in env.items():
        if not isinstance(k, str) or not k.strip() or not isinstance(v, str):
            raise SchemaValidationError("env must map strings to strings (fail-closed)")

    cmds = entry.get("commands_executed")
    if not isinstance(cmds, dict) or not cmds:
        raise SchemaValidationError("commands_executed must be non-empty object (fail-closed)")
    for k, v in cmds.items():
        if not isinstance(k, str) or not k.strip():
            raise SchemaValidationError("commands_executed keys must be non-empty strings (fail-closed)")
        if not isinstance(v, list) or not v or not all(isinstance(x, str) and x.strip() for x in v):
            raise SchemaValidationError("commands_executed values must be non-empty list of strings (fail-closed)")

    arts = entry.get("artifacts")
    if not isinstance(arts, dict) or not arts:
        raise SchemaValidationError("artifacts must be non-empty object (fail-closed)")
    for k, v in arts.items():
        if not isinstance(k, str) or not k.strip() or not isinstance(v, str) or not v.strip():
            raise SchemaValidationError("artifacts must map non-empty strings to non-empty strings (fail-closed)")
