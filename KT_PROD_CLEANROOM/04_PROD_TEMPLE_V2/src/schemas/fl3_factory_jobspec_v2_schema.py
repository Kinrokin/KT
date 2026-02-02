from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64, validate_short_string
from schemas.fl3_schema_common import sha256_hex_of_obj
from schemas.schema_files import schema_version_hash


FL3_FACTORY_JOBSPEC_V2_SCHEMA_ID = "kt.factory.jobspec.v2"
FL3_FACTORY_JOBSPEC_V2_SCHEMA_FILE = "fl3/kt.factory.jobspec.v2.json"
FL3_FACTORY_JOBSPEC_V2_SCHEMA_VERSION_HASH = schema_version_hash(FL3_FACTORY_JOBSPEC_V2_SCHEMA_FILE)

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
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {"tournament", "breeding"}
_HASH_DROP_KEYS: Set[str] = {"job_id"}


def validate_fl3_factory_jobspec_v2(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 jobspec v2")
    enforce_max_fields(entry, max_fields=64)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_FACTORY_JOBSPEC_V2_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_FACTORY_JOBSPEC_V2_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "job_id")
    validate_short_string(entry, "adapter_id", max_len=128)
    validate_short_string(entry, "adapter_version", max_len=64)
    validate_short_string(entry, "role", max_len=64)
    if entry.get("mode") not in {"SMOKE", "STANDARD", "SOVEREIGN", "SHADOW"}:
        raise SchemaValidationError("mode invalid (fail-closed)")
    run_kind = entry.get("run_kind")
    if run_kind not in {"STANDARD", "VRR", "TOURNAMENT", "BREEDING"}:
        raise SchemaValidationError("run_kind invalid (fail-closed)")
    validate_short_string(entry, "base_model_id", max_len=128)
    if entry.get("training_mode") not in {"lora", "head_only"}:
        raise SchemaValidationError("training_mode invalid (fail-closed)")
    if not isinstance(entry.get("seed"), int):
        raise SchemaValidationError("seed must be int (fail-closed)")
    validate_short_string(entry, "export_shadow_root", max_len=256)
    validate_short_string(entry, "export_promoted_root", max_len=256)

    if run_kind == "TOURNAMENT" and not isinstance(entry.get("tournament"), dict):
        raise SchemaValidationError("TOURNAMENT run_kind requires tournament object (fail-closed)")
    if run_kind == "BREEDING":
        breeding = entry.get("breeding")
        if not isinstance(breeding, dict):
            raise SchemaValidationError("BREEDING run_kind requires breeding object (fail-closed)")
        bf = breeding.get("batch_fraction")
        if not isinstance(bf, (int, float)) or bf <= 0.0 or bf > 1.0:
            raise SchemaValidationError("breeding.batch_fraction must be in (0,1] (fail-closed)")
        sources = breeding.get("shadow_sources")
        if not isinstance(sources, list) or not all(isinstance(x, str) and x.strip() for x in sources):
            raise SchemaValidationError("breeding.shadow_sources must be list of non-empty strings (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("job_id") != expected:
        raise SchemaValidationError("job_id does not match canonical hash surface (fail-closed)")

