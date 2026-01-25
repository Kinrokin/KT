from __future__ import annotations

from typing import Any, Callable, Dict, Mapping, Tuple

from schemas.base_schema import SchemaRegistryError, SchemaValidationError, require_dict
from schemas.runtime_context_schema import (
    RUNTIME_CONTEXT_SCHEMA_ID,
    RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
    validate_runtime_context,
)
from schemas.state_vault_schema import (
    STATE_VAULT_SCHEMA_ID,
    STATE_VAULT_SCHEMA_VERSION_HASH,
    validate_state_vault_record,
)
from schemas.routing_record_schema import (
    ROUTING_RECORD_SCHEMA_ID,
    ROUTING_RECORD_SCHEMA_VERSION_HASH,
    validate_routing_record,
)
from schemas.adapter_invocation_schema import (
    ADAPTER_INVOCATION_SCHEMA_ID,
    ADAPTER_INVOCATION_SCHEMA_VERSION_HASH,
    validate_adapter_invocation,
)
from schemas.runtime_registry_schema import (
    RUNTIME_REGISTRY_SCHEMA_ID,
    RUNTIME_REGISTRY_SCHEMA_VERSION_HASH,
    validate_runtime_registry,
)
from schemas.task_context_schema import (
    TASK_CONTEXT_SCHEMA_ID,
    TASK_CONTEXT_SCHEMA_VERSION_HASH,
    validate_task_context,
)
from schemas.evaluator_battery_manifest_schema import (
    EVALUATOR_BATTERY_MANIFEST_SCHEMA_ID,
    EVALUATOR_BATTERY_MANIFEST_SCHEMA_VERSION_HASH,
    validate_evaluator_battery_manifest,
)
from schemas.evaluator_result_schema import (
    EVALUATOR_RESULT_SCHEMA_ID,
    EVALUATOR_RESULT_SCHEMA_VERSION_HASH,
    validate_evaluator_result,
)


_Validator = Callable[[Dict[str, Any]], None]


SCHEMA_REGISTRY: Mapping[str, Tuple[str, _Validator]] = {
    # NOTE: append-only. New schemas are added explicitly with new IDs/hashes.
    RUNTIME_CONTEXT_SCHEMA_ID: (RUNTIME_CONTEXT_SCHEMA_VERSION_HASH, validate_runtime_context),
    STATE_VAULT_SCHEMA_ID: (STATE_VAULT_SCHEMA_VERSION_HASH, validate_state_vault_record),
    ROUTING_RECORD_SCHEMA_ID: (ROUTING_RECORD_SCHEMA_VERSION_HASH, validate_routing_record),
    ADAPTER_INVOCATION_SCHEMA_ID: (ADAPTER_INVOCATION_SCHEMA_VERSION_HASH, validate_adapter_invocation),
    RUNTIME_REGISTRY_SCHEMA_ID: (RUNTIME_REGISTRY_SCHEMA_VERSION_HASH, validate_runtime_registry),
    TASK_CONTEXT_SCHEMA_ID: (TASK_CONTEXT_SCHEMA_VERSION_HASH, validate_task_context),
    EVALUATOR_BATTERY_MANIFEST_SCHEMA_ID: (
        EVALUATOR_BATTERY_MANIFEST_SCHEMA_VERSION_HASH,
        validate_evaluator_battery_manifest,
    ),
    EVALUATOR_RESULT_SCHEMA_ID: (EVALUATOR_RESULT_SCHEMA_VERSION_HASH, validate_evaluator_result),
}


def validate_schema_binding(schema_id: str, schema_version_hash: str) -> None:
    if schema_id not in SCHEMA_REGISTRY:
        raise SchemaRegistryError(f"Unknown schema_id (fail-closed): {schema_id!r}")
    expected_hash, _validator = SCHEMA_REGISTRY[schema_id]
    if schema_version_hash != expected_hash:
        raise SchemaRegistryError("schema_version_hash mismatch vs registry (fail-closed)")


def validate(schema_id: str, payload: Dict[str, Any]) -> None:
    if schema_id not in SCHEMA_REGISTRY:
        raise SchemaRegistryError(f"Unknown schema_id (fail-closed): {schema_id!r}")
    _expected_hash, validator = SCHEMA_REGISTRY[schema_id]
    validator(payload)


def validate_object_with_binding(payload: Any) -> None:
    obj = require_dict(payload, name="Schema-bound object")
    schema_id = obj.get("schema_id")
    schema_version_hash = obj.get("schema_version_hash")
    if not isinstance(schema_id, str):
        raise SchemaValidationError("schema_id must be a string")
    if not isinstance(schema_version_hash, str):
        raise SchemaValidationError("schema_version_hash must be a string")
    validate_schema_binding(schema_id, schema_version_hash)
    validate(schema_id, obj)
