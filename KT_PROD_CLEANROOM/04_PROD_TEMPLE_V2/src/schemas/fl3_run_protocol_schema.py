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
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_RUN_PROTOCOL_SCHEMA_ID = "kt.run_protocol.v1"
FL3_RUN_PROTOCOL_SCHEMA_FILE = "fl3/kt.run_protocol.v1.json"
FL3_RUN_PROTOCOL_SCHEMA_VERSION_HASH = schema_version_hash(FL3_RUN_PROTOCOL_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "run_protocol_id",
    "run_id",
    "lane_id",
    "timestamp_utc",
    "determinism_mode",
    "execution_environment_hash",
    "governed_phase_start_hash",
    "io_guard_status",
    "base_model_id",
    "active_adapters",
    "replay_command",
    "replay_script_hash",
    "run_protocol_json_hash",
    "run_protocol_md_hash",
    "secret_scan_result",
    "bundle_root_hash",
    "created_at",
)
_OPTIONAL_ORDER = (
    "bootstrap_receipt_hash",
    "base_model_commit",
    "active_laws",
    "datasets",
    "notes",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)


def _validate_sorted_string_list(value: Any, *, field: str) -> None:
    if not isinstance(value, list):
        raise SchemaValidationError(f"{field} must be a list (fail-closed)")
    if not all(isinstance(x, str) and x.strip() for x in value):
        raise SchemaValidationError(f"{field} must contain non-empty strings (fail-closed)")
    stripped = [str(x).strip() for x in value]
    if stripped != sorted(stripped):
        raise SchemaValidationError(f"{field} must be sorted (fail-closed)")


def _validate_adapter_entry(obj: Any) -> None:
    entry = require_dict(obj, name="active_adapters[]")
    allowed = {"adapter_id", "adapter_hash", "adapter_profile_hash"}
    required = {"adapter_id", "adapter_hash"}
    require_keys(entry, required=required)
    reject_unknown_keys(entry, allowed=allowed)
    validate_short_string(entry, "adapter_id", max_len=128)
    validate_hex_64(entry, "adapter_hash")

    if "adapter_profile_hash" in entry and entry["adapter_profile_hash"] is not None:
        validate_hex_64(entry, "adapter_profile_hash")


def _validate_dataset_entry(obj: Any) -> None:
    entry = require_dict(obj, name="datasets[]")
    require_keys(entry, required={"relpath", "sha256"})
    reject_unknown_keys(entry, allowed={"relpath", "sha256"})
    validate_short_string(entry, "relpath", max_len=1024)
    validate_hex_64(entry, "sha256")


def validate_fl3_run_protocol(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 run protocol")
    enforce_max_fields(entry, max_fields=40)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    enforce_max_canonical_json_bytes(entry, max_bytes=256 * 1024)

    if entry.get("schema_id") != FL3_RUN_PROTOCOL_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_RUN_PROTOCOL_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "run_protocol_id")
    validate_hex_64(entry, "execution_environment_hash")
    validate_hex_64(entry, "governed_phase_start_hash")
    validate_hex_64(entry, "replay_script_hash")
    validate_hex_64(entry, "run_protocol_json_hash")
    validate_hex_64(entry, "run_protocol_md_hash")
    validate_hex_64(entry, "bundle_root_hash")

    validate_short_string(entry, "run_id", max_len=128)
    validate_short_string(entry, "lane_id", max_len=64)
    validate_short_string(entry, "base_model_id", max_len=256)
    validate_short_string(entry, "replay_command", max_len=4096)
    validate_created_at_utc_z(entry.get("timestamp_utc"))
    validate_created_at_utc_z(entry.get("created_at"))

    if entry.get("determinism_mode") not in {"STRICT", "PRACTICAL"}:
        raise SchemaValidationError("determinism_mode must be STRICT or PRACTICAL (fail-closed)")
    if entry.get("io_guard_status") not in {"OFFLINE", "GUARDED", "BYPASS"}:
        raise SchemaValidationError("io_guard_status must be OFFLINE, GUARDED, or BYPASS (fail-closed)")
    if entry.get("secret_scan_result") not in {"PASS", "FAIL", "ERROR"}:
        raise SchemaValidationError("secret_scan_result must be PASS, FAIL, or ERROR (fail-closed)")

    if "bootstrap_receipt_hash" in entry and entry["bootstrap_receipt_hash"] is not None:
        validate_hex_64(entry, "bootstrap_receipt_hash")
    if "base_model_commit" in entry and entry["base_model_commit"] is not None:
        validate_short_string(entry, "base_model_commit", max_len=256)
    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    adapters = entry.get("active_adapters")
    if not isinstance(adapters, list) or len(adapters) < 1:
        raise SchemaValidationError("active_adapters must be a non-empty list (fail-closed)")
    for a in adapters:
        _validate_adapter_entry(a)

    if "active_laws" in entry:
        _validate_sorted_string_list(entry.get("active_laws"), field="active_laws")

    if "datasets" in entry:
        datasets = entry.get("datasets")
        if not isinstance(datasets, list):
            raise SchemaValidationError("datasets must be a list when present (fail-closed)")
        for d in datasets:
            _validate_dataset_entry(d)

    expected_id = sha256_hex_of_obj(
        entry,
        drop_keys={"created_at", "run_protocol_id", "run_protocol_json_hash", "run_protocol_md_hash"},
    )
    if entry.get("run_protocol_id") != expected_id:
        raise SchemaValidationError("run_protocol_id does not match canonical hash surface (fail-closed)")

    expected_json_hash = sha256_hex_of_obj(entry, drop_keys={"run_protocol_json_hash"})
    if entry.get("run_protocol_json_hash") != expected_json_hash:
        raise SchemaValidationError("run_protocol_json_hash does not match canonical payload (fail-closed)")
