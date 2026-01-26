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
from schemas.fl3_blind_judgement_pack_schema import (
    FL3_BLIND_JUDGEMENT_PACK_SCHEMA_ID,
    FL3_BLIND_JUDGEMENT_PACK_SCHEMA_VERSION_HASH,
    validate_fl3_blind_judgement_pack,
)
from schemas.fl3_factory_jobspec_schema import (
    FL3_FACTORY_JOBSPEC_SCHEMA_ID,
    FL3_FACTORY_JOBSPEC_SCHEMA_VERSION_HASH,
    validate_fl3_factory_jobspec,
)
from schemas.fl3_factory_dataset_schema import (
    FL3_FACTORY_DATASET_SCHEMA_ID,
    FL3_FACTORY_DATASET_SCHEMA_VERSION_HASH,
    validate_fl3_factory_dataset,
)
from schemas.fl3_factory_eval_report_schema import (
    FL3_FACTORY_EVAL_REPORT_SCHEMA_ID,
    FL3_FACTORY_EVAL_REPORT_SCHEMA_VERSION_HASH,
    validate_fl3_factory_eval_report,
)
from schemas.fl3_factory_freeze_receipt_schema import (
    FL3_FACTORY_FREEZE_RECEIPT_SCHEMA_ID,
    FL3_FACTORY_FREEZE_RECEIPT_SCHEMA_VERSION_HASH,
    validate_fl3_factory_freeze_receipt,
)
from schemas.fl3_factory_judgement_schema import (
    FL3_FACTORY_JUDGEMENT_SCHEMA_ID,
    FL3_FACTORY_JUDGEMENT_SCHEMA_VERSION_HASH,
    validate_fl3_factory_judgement,
)
from schemas.fl3_factory_promotion_schema import (
    FL3_FACTORY_PROMOTION_SCHEMA_ID,
    FL3_FACTORY_PROMOTION_SCHEMA_VERSION_HASH,
    validate_fl3_factory_promotion,
)
from schemas.fl3_factory_train_manifest_schema import (
    FL3_FACTORY_TRAIN_MANIFEST_SCHEMA_ID,
    FL3_FACTORY_TRAIN_MANIFEST_SCHEMA_VERSION_HASH,
    validate_fl3_factory_train_manifest,
)
from schemas.fl3_factory_organ_contract_schema import (
    FL3_FACTORY_ORGAN_CONTRACT_SCHEMA_ID,
    FL3_FACTORY_ORGAN_CONTRACT_SCHEMA_VERSION_HASH,
    validate_fl3_factory_organ_contract,
)
from schemas.fl3_failure_contract_schema import (
    FL3_FAILURE_CONTRACT_SCHEMA_ID,
    FL3_FAILURE_CONTRACT_SCHEMA_VERSION_HASH,
    validate_fl3_failure_contract,
)
from schemas.fl3_global_budget_state_schema import (
    FL3_GLOBAL_BUDGET_STATE_SCHEMA_ID,
    FL3_GLOBAL_BUDGET_STATE_SCHEMA_VERSION_HASH,
    validate_fl3_global_budget_state,
)
from schemas.fl3_global_unlock_schema import (
    FL3_GLOBAL_UNLOCK_SCHEMA_ID,
    FL3_GLOBAL_UNLOCK_SCHEMA_VERSION_HASH,
    validate_fl3_global_unlock,
)
from schemas.fl3_human_signoff_schema import (
    FL3_HUMAN_SIGNOFF_SCHEMA_ID,
    FL3_HUMAN_SIGNOFF_SCHEMA_VERSION_HASH,
    validate_fl3_human_signoff,
)
from schemas.fl3_law_amendment_schema import (
    FL3_LAW_AMENDMENT_SCHEMA_ID,
    FL3_LAW_AMENDMENT_SCHEMA_VERSION_HASH,
    validate_fl3_law_amendment,
)
from schemas.fl3_reasoning_trace_schema import (
    FL3_REASONING_TRACE_SCHEMA_ID,
    FL3_REASONING_TRACE_SCHEMA_VERSION_HASH,
    validate_fl3_reasoning_trace,
)
from schemas.fl3_reveal_mapping_schema import (
    FL3_REVEAL_MAPPING_SCHEMA_ID,
    FL3_REVEAL_MAPPING_SCHEMA_VERSION_HASH,
    validate_fl3_reveal_mapping,
)
from schemas.fl3_signal_quality_schema import (
    FL3_SIGNAL_QUALITY_SCHEMA_ID,
    FL3_SIGNAL_QUALITY_SCHEMA_VERSION_HASH,
    validate_fl3_signal_quality,
)
from schemas.fl3_tournament_manifest_schema import (
    FL3_TOURNAMENT_MANIFEST_SCHEMA_ID,
    FL3_TOURNAMENT_MANIFEST_SCHEMA_VERSION_HASH,
    validate_fl3_tournament_manifest,
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
    # FL3: factory/law schemas (append-only).
    FL3_FACTORY_ORGAN_CONTRACT_SCHEMA_ID: (
        FL3_FACTORY_ORGAN_CONTRACT_SCHEMA_VERSION_HASH,
        validate_fl3_factory_organ_contract,
    ),
    FL3_GLOBAL_BUDGET_STATE_SCHEMA_ID: (FL3_GLOBAL_BUDGET_STATE_SCHEMA_VERSION_HASH, validate_fl3_global_budget_state),
    FL3_HUMAN_SIGNOFF_SCHEMA_ID: (FL3_HUMAN_SIGNOFF_SCHEMA_VERSION_HASH, validate_fl3_human_signoff),
    FL3_GLOBAL_UNLOCK_SCHEMA_ID: (FL3_GLOBAL_UNLOCK_SCHEMA_VERSION_HASH, validate_fl3_global_unlock),
    FL3_FACTORY_JOBSPEC_SCHEMA_ID: (FL3_FACTORY_JOBSPEC_SCHEMA_VERSION_HASH, validate_fl3_factory_jobspec),
    FL3_FACTORY_DATASET_SCHEMA_ID: (FL3_FACTORY_DATASET_SCHEMA_VERSION_HASH, validate_fl3_factory_dataset),
    FL3_FACTORY_JUDGEMENT_SCHEMA_ID: (FL3_FACTORY_JUDGEMENT_SCHEMA_VERSION_HASH, validate_fl3_factory_judgement),
    FL3_FACTORY_TRAIN_MANIFEST_SCHEMA_ID: (
        FL3_FACTORY_TRAIN_MANIFEST_SCHEMA_VERSION_HASH,
        validate_fl3_factory_train_manifest,
    ),
    FL3_FACTORY_EVAL_REPORT_SCHEMA_ID: (FL3_FACTORY_EVAL_REPORT_SCHEMA_VERSION_HASH, validate_fl3_factory_eval_report),
    FL3_FACTORY_PROMOTION_SCHEMA_ID: (FL3_FACTORY_PROMOTION_SCHEMA_VERSION_HASH, validate_fl3_factory_promotion),
    FL3_FACTORY_FREEZE_RECEIPT_SCHEMA_ID: (
        FL3_FACTORY_FREEZE_RECEIPT_SCHEMA_VERSION_HASH,
        validate_fl3_factory_freeze_receipt,
    ),
    FL3_REASONING_TRACE_SCHEMA_ID: (FL3_REASONING_TRACE_SCHEMA_VERSION_HASH, validate_fl3_reasoning_trace),
    FL3_TOURNAMENT_MANIFEST_SCHEMA_ID: (
        FL3_TOURNAMENT_MANIFEST_SCHEMA_VERSION_HASH,
        validate_fl3_tournament_manifest,
    ),
    FL3_BLIND_JUDGEMENT_PACK_SCHEMA_ID: (FL3_BLIND_JUDGEMENT_PACK_SCHEMA_VERSION_HASH, validate_fl3_blind_judgement_pack),
    FL3_REVEAL_MAPPING_SCHEMA_ID: (FL3_REVEAL_MAPPING_SCHEMA_VERSION_HASH, validate_fl3_reveal_mapping),
    FL3_SIGNAL_QUALITY_SCHEMA_ID: (FL3_SIGNAL_QUALITY_SCHEMA_VERSION_HASH, validate_fl3_signal_quality),
    FL3_FAILURE_CONTRACT_SCHEMA_ID: (FL3_FAILURE_CONTRACT_SCHEMA_VERSION_HASH, validate_fl3_failure_contract),
    FL3_LAW_AMENDMENT_SCHEMA_ID: (FL3_LAW_AMENDMENT_SCHEMA_VERSION_HASH, validate_fl3_law_amendment),
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
