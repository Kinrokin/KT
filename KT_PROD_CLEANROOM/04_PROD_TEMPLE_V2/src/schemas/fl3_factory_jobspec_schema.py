from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64, validate_short_string
from schemas.fl3_schema_common import sha256_hex_of_obj
from schemas.schema_files import schema_version_hash


FL3_FACTORY_JOBSPEC_SCHEMA_ID = "kt.factory.jobspec.v1"
FL3_FACTORY_JOBSPEC_SCHEMA_FILE = "fl3/kt.factory.jobspec.v1.json"
FL3_FACTORY_JOBSPEC_SCHEMA_VERSION_HASH = schema_version_hash(FL3_FACTORY_JOBSPEC_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "job_id",
    "adapter_id",
    "adapter_version",
    "role",
    "mode",
    "run_kind",
    "base_model_id",
    "training_mode",
    "seed",
    "export_shadow_root",
    "export_promoted_root",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"job_id"}


def validate_fl3_factory_jobspec(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 factory jobspec")
    enforce_max_fields(entry, max_fields=32)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_FACTORY_JOBSPEC_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_FACTORY_JOBSPEC_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "job_id")
    validate_short_string(entry, "adapter_id", max_len=128)
    validate_short_string(entry, "adapter_version", max_len=64)
    validate_short_string(entry, "role", max_len=64)

    mode = entry.get("mode")
    if mode not in {"SMOKE", "STANDARD", "SOVEREIGN", "SHADOW"}:
        raise SchemaValidationError("mode invalid (fail-closed)")
    run_kind = entry.get("run_kind")
    if run_kind not in {"STANDARD", "VRR", "TOURNAMENT"}:
        raise SchemaValidationError("run_kind invalid (fail-closed)")
    training_mode = entry.get("training_mode")
    if training_mode not in {"lora", "head_only"}:
        raise SchemaValidationError("training_mode invalid (fail-closed)")

    validate_short_string(entry, "base_model_id", max_len=128)
    seed = entry.get("seed")
    if not isinstance(seed, int):
        raise SchemaValidationError("seed must be integer (fail-closed)")

    # Factory output roots are jailed to cleanroom exports by contract.
    shadow_root = entry.get("export_shadow_root")
    promoted_root = entry.get("export_promoted_root")
    if not isinstance(shadow_root, str) or not shadow_root.startswith("KT_PROD_CLEANROOM/exports/adapters_shadow"):
        raise SchemaValidationError("export_shadow_root must be under exports/adapters_shadow (fail-closed)")
    if not isinstance(promoted_root, str) or not promoted_root.startswith("KT_PROD_CLEANROOM/exports/adapters"):
        raise SchemaValidationError("export_promoted_root must be under exports/adapters (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("job_id") != expected:
        raise SchemaValidationError("job_id does not match canonical hash surface (fail-closed)")

