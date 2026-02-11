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


FL4_PREFLIGHT_SUMMARY_SCHEMA_ID = "kt.fl4.preflight_summary.v1"
FL4_PREFLIGHT_SUMMARY_SCHEMA_FILE = "fl3/kt.fl4.preflight_summary.v1.json"
FL4_PREFLIGHT_SUMMARY_SCHEMA_VERSION_HASH = schema_version_hash(FL4_PREFLIGHT_SUMMARY_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "git_sha",
    "out_dir",
    "registry_path",
    "job_id",
    "job_dir",
    "evidence_job_dir",
    "seal_doctrine_sha256",
    "env_lock_id",
    "fl3_pressure_growth_gate",
)
_OPTIONAL_ORDER = (
    "behavioral_growth",
    "promoted_dir",
    "promoted_index_path",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)


def validate_fl4_preflight_summary(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL4 preflight summary")
    enforce_max_fields(entry, max_fields=32)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    enforce_max_canonical_json_bytes(entry, max_bytes=128 * 1024)

    if entry.get("schema_id") != FL4_PREFLIGHT_SUMMARY_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL4_PREFLIGHT_SUMMARY_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_short_string(entry, "git_sha", max_len=64)
    validate_short_string(entry, "out_dir", max_len=512)
    validate_short_string(entry, "registry_path", max_len=512)
    validate_hex_64(entry, "job_id")
    validate_short_string(entry, "job_dir", max_len=1024)
    validate_short_string(entry, "evidence_job_dir", max_len=1024)
    validate_hex_64(entry, "seal_doctrine_sha256")
    validate_hex_64(entry, "env_lock_id")

    gate = require_dict(entry.get("fl3_pressure_growth_gate"), name="fl3_pressure_growth_gate")
    if set(gate.keys()) != {"executed", "receipt"}:
        raise SchemaValidationError("fl3_pressure_growth_gate keys mismatch (fail-closed)")
    if not isinstance(gate.get("executed"), bool):
        raise SchemaValidationError("fl3_pressure_growth_gate.executed must be boolean (fail-closed)")
    if not isinstance(gate.get("receipt"), str) or not gate["receipt"].strip():
        raise SchemaValidationError("fl3_pressure_growth_gate.receipt must be non-empty string (fail-closed)")

    if "promoted_dir" in entry and (not isinstance(entry["promoted_dir"], str) or not entry["promoted_dir"].strip()):
        raise SchemaValidationError("promoted_dir must be non-empty string when present (fail-closed)")
    if "promoted_index_path" in entry and (
        not isinstance(entry["promoted_index_path"], str) or not entry["promoted_index_path"].strip()
    ):
        raise SchemaValidationError("promoted_index_path must be non-empty string when present (fail-closed)")
    if "behavioral_growth" in entry and not isinstance(entry["behavioral_growth"], dict):
        raise SchemaValidationError("behavioral_growth must be object when present (fail-closed)")

