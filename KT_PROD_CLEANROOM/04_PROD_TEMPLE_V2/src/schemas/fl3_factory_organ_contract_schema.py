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

    _ = ensure_sorted_str_list(entry.get("allowed_base_models"), field="allowed_base_models")
    _ = ensure_sorted_str_list(entry.get("allowed_training_modes"), field="allowed_training_modes")
    _ = ensure_sorted_str_list(entry.get("allowed_output_schemas"), field="allowed_output_schemas")
    _ = ensure_sorted_str_list(entry.get("allowed_export_roots"), field="allowed_export_roots")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("contract_id") != expected:
        raise SchemaValidationError("contract_id does not match canonical hash surface (fail-closed)")

