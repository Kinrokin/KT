from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64
from schemas.fl3_schema_common import ensure_sorted_str_list, sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_FACTORY_ORGAN_CONTRACT_SCHEMA_ID = "kt.factory.organ_contract.v1"
FL3_FACTORY_ORGAN_CONTRACT_SCHEMA_FILE = "fl3/kt.factory.organ_contract.v1.json"
FL3_FACTORY_ORGAN_CONTRACT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_FACTORY_ORGAN_CONTRACT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "contract_id",
    "entrypoints",
    "allowed_base_models",
    "allowed_training_modes",
    "allowed_output_schemas",
    "allowed_export_roots",
    "created_at",
)

_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "contract_id"}


def validate_fl3_factory_organ_contract(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 factory organ contract")
    enforce_max_fields(entry, max_fields=32)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_FACTORY_ORGAN_CONTRACT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_FACTORY_ORGAN_CONTRACT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "contract_id")
    validate_created_at_utc_z(entry.get("created_at"))

    _validate_entrypoints(entry.get("entrypoints"))

    _ = ensure_sorted_str_list(entry.get("allowed_base_models"), field="allowed_base_models")
    _ = ensure_sorted_str_list(entry.get("allowed_training_modes"), field="allowed_training_modes")
    _ = ensure_sorted_str_list(entry.get("allowed_output_schemas"), field="allowed_output_schemas")
    _ = ensure_sorted_str_list(entry.get("allowed_export_roots"), field="allowed_export_roots")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("contract_id") != expected:
        raise SchemaValidationError("contract_id does not match canonical hash surface (fail-closed)")


def _validate_entrypoints(value: Any) -> None:
    entry = require_dict(value, name="entrypoints")
    # Must at least define run_job. Other phases may be added later without schema change by extending
    # the contract instance - schema enforces only known keys.
    if "run_job" not in entry:
        raise SchemaValidationError("entrypoints.run_job required (fail-closed)")
    for k, v in entry.items():
        if k not in {"run_job", "harvest", "judge", "train", "evaluate", "promote", "register", "freeze"}:
            raise SchemaValidationError("entrypoints contains unknown key (fail-closed)")
        item = require_dict(v, name=f"entrypoints.{k}")
        if set(item.keys()) != {"path", "sha256"}:
            raise SchemaValidationError(f"entrypoints.{k} must have keys path,sha256 (fail-closed)")
        if not isinstance(item.get("path"), str) or not item["path"].strip():
            raise SchemaValidationError(f"entrypoints.{k}.path must be non-empty string (fail-closed)")
        validate_hex_64(item, "sha256")
