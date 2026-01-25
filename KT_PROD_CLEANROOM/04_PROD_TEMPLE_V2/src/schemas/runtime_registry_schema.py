from __future__ import annotations

from typing import Any, Dict, Set

from schemas.adapter_entry_schema import ADAPTER_ENTRY_SCHEMA_ID, ADAPTER_ENTRY_SCHEMA_VERSION_HASH, validate_adapter_entry
from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_hex_64,
    validate_short_string,
)
from schemas.schema_files import schema_version_hash


RUNTIME_REGISTRY_SCHEMA_ID = "kt.runtime_registry.v1"
RUNTIME_REGISTRY_SCHEMA_FILE = "kt.runtime.registry.v1.json"
RUNTIME_REGISTRY_SCHEMA_VERSION_HASH = schema_version_hash(RUNTIME_REGISTRY_SCHEMA_FILE)

RUNTIME_REGISTRY_REQUIRED_FIELDS_ORDER = (
    "schema_id",
    "schema_version_hash",
    "registry_version",
    "canonical_entry",
    "canonical_spine",
    "state_vault",
    "runtime_import_roots",
    "organs_by_root",
    "import_truth_matrix",
    "dry_run",
    "policy_c",
    "adapters",
)

RUNTIME_REGISTRY_REQUIRED_FIELDS: Set[str] = set(RUNTIME_REGISTRY_REQUIRED_FIELDS_ORDER)
RUNTIME_REGISTRY_ALLOWED_FIELDS: Set[str] = set(RUNTIME_REGISTRY_REQUIRED_FIELDS_ORDER)


def validate_runtime_registry(payload: Dict[str, Any]) -> None:
    require_dict(payload, name="Runtime registry")
    enforce_max_fields(payload, max_fields=32)
    require_keys(payload, required=RUNTIME_REGISTRY_REQUIRED_FIELDS)
    reject_unknown_keys(payload, allowed=RUNTIME_REGISTRY_ALLOWED_FIELDS)

    validate_short_string(payload, "schema_id", max_len=64)
    validate_hex_64(payload, "schema_version_hash")

    if payload["schema_id"] != RUNTIME_REGISTRY_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if payload["schema_version_hash"] != RUNTIME_REGISTRY_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    if payload.get("registry_version") != "1":
        raise SchemaValidationError("registry_version must be '1' (fail-closed)")

    _validate_callable_spec(payload.get("canonical_entry"), "canonical_entry")
    _validate_callable_spec(payload.get("canonical_spine"), "canonical_spine")
    _validate_state_vault(payload.get("state_vault"))
    _validate_string_list(payload.get("runtime_import_roots"), "runtime_import_roots")
    _validate_mapping(payload.get("organs_by_root"), "organs_by_root")
    _validate_matrix(payload.get("import_truth_matrix"))
    _validate_dry_run(payload.get("dry_run"))
    _validate_policy_c(payload.get("policy_c"))
    _validate_adapters(payload.get("adapters"))


def _validate_callable_spec(value: Any, name: str) -> None:
    entry = require_dict(value, name=name)
    require_keys(entry, required={"module", "callable"})
    reject_unknown_keys(entry, allowed={"module", "callable"})
    validate_short_string(entry, "module", max_len=128)
    validate_short_string(entry, "callable", max_len=64)


def _validate_state_vault(value: Any) -> None:
    entry = require_dict(value, name="state_vault")
    require_keys(entry, required={"jsonl_path"})
    reject_unknown_keys(entry, allowed={"jsonl_path"})
    validate_short_string(entry, "jsonl_path", max_len=256)


def _validate_string_list(value: Any, name: str) -> None:
    if not isinstance(value, list) or not value:
        raise SchemaValidationError(f"{name} must be a non-empty list (fail-closed)")
    if not all(isinstance(x, str) and x.strip() for x in value):
        raise SchemaValidationError(f"{name} must contain non-empty strings (fail-closed)")


def _validate_mapping(value: Any, name: str) -> None:
    entry = require_dict(value, name=name)
    for k, v in entry.items():
        if not isinstance(k, str) or not isinstance(v, str) or not k.strip() or not v.strip():
            raise SchemaValidationError(f"{name} must map strings to strings (fail-closed)")


def _validate_matrix(value: Any) -> None:
    entry = require_dict(value, name="import_truth_matrix")
    for k, v in entry.items():
        if not isinstance(k, str) or not k.strip():
            raise SchemaValidationError("import_truth_matrix keys must be strings (fail-closed)")
        if not isinstance(v, list) or not all(isinstance(x, str) and x.strip() for x in v):
            raise SchemaValidationError("import_truth_matrix values must be list of strings (fail-closed)")


def _validate_dry_run(value: Any) -> None:
    entry = require_dict(value, name="dry_run")
    require_keys(entry, required={"no_network", "providers_enabled"})
    reject_unknown_keys(entry, allowed={"no_network", "providers_enabled"})
    if not isinstance(entry.get("no_network"), bool) or not isinstance(entry.get("providers_enabled"), bool):
        raise SchemaValidationError("dry_run flags must be booleans (fail-closed)")


def _validate_policy_c(value: Any) -> None:
    entry = require_dict(value, name="policy_c")
    require_keys(entry, required={"drift", "sweep", "static_safety"})
    reject_unknown_keys(entry, allowed={"drift", "sweep", "static_safety"})


def _validate_adapters(value: Any) -> None:
    entry = require_dict(value, name="adapters")
    require_keys(entry, required={"registry_schema_id", "allowed_export_roots", "entries"})
    reject_unknown_keys(entry, allowed={"registry_schema_id", "allowed_export_roots", "entries"})
    validate_short_string(entry, "registry_schema_id", max_len=128)
    if entry.get("registry_schema_id") != "kt.adapters.registry.v1":
        raise SchemaValidationError("adapters.registry_schema_id mismatch (fail-closed)")
    _validate_string_list(entry.get("allowed_export_roots"), "adapters.allowed_export_roots")
    entries = entry.get("entries")
    if not isinstance(entries, list):
        raise SchemaValidationError("adapters.entries must be a list (fail-closed)")
    for item in entries:
        validate_adapter_entry(require_dict(item, name="adapter entry"))
        if item.get("schema_id") != ADAPTER_ENTRY_SCHEMA_ID:
            raise SchemaValidationError("adapter entry schema_id mismatch (fail-closed)")
        if item.get("schema_version_hash") != ADAPTER_ENTRY_SCHEMA_VERSION_HASH:
            raise SchemaValidationError("adapter entry schema_version_hash mismatch (fail-closed)")
