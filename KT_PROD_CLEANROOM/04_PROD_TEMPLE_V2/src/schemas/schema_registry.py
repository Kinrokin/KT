from __future__ import annotations

import importlib
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
from schemas.fl3_factory_jobspec_v2_schema import (
    FL3_FACTORY_JOBSPEC_V2_SCHEMA_ID,
    FL3_FACTORY_JOBSPEC_V2_SCHEMA_VERSION_HASH,
    validate_fl3_factory_jobspec_v2,
)
from schemas.fl3_factory_eval_report_schema import (
    FL3_FACTORY_EVAL_REPORT_SCHEMA_ID,
    FL3_FACTORY_EVAL_REPORT_SCHEMA_VERSION_HASH,
    validate_fl3_factory_eval_report,
)
from schemas.fl3_factory_eval_report_v2_schema import (
    FL3_FACTORY_EVAL_REPORT_V2_SCHEMA_ID,
    FL3_FACTORY_EVAL_REPORT_V2_SCHEMA_VERSION_HASH,
    validate_fl3_factory_eval_report_v2,
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
from schemas.fl3_factory_job_dir_manifest_schema import (
    FL3_FACTORY_JOB_DIR_MANIFEST_SCHEMA_ID,
    FL3_FACTORY_JOB_DIR_MANIFEST_SCHEMA_VERSION_HASH,
    validate_fl3_factory_job_dir_manifest,
)
from schemas.fl3_factory_phase_trace_schema import (
    FL3_FACTORY_PHASE_TRACE_SCHEMA_ID,
    FL3_FACTORY_PHASE_TRACE_SCHEMA_VERSION_HASH,
    validate_fl3_factory_phase_trace,
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
from schemas.fl3_breeding_manifest_schema import (
    FL3_BREEDING_MANIFEST_SCHEMA_ID,
    FL3_BREEDING_MANIFEST_SCHEMA_VERSION_HASH,
    validate_fl3_breeding_manifest,
)
from schemas.fl3_epigenetic_summary_schema import (
    FL3_EPIGENETIC_SUMMARY_SCHEMA_ID,
    FL3_EPIGENETIC_SUMMARY_SCHEMA_VERSION_HASH,
    validate_fl3_epigenetic_summary,
)
from schemas.fl3_fitness_policy_schema import (
    FL3_FITNESS_POLICY_SCHEMA_ID,
    FL3_FITNESS_POLICY_SCHEMA_VERSION_HASH,
    validate_fl3_fitness_policy,
)
from schemas.fl3_fitness_region_schema import (
    FL3_FITNESS_REGION_SCHEMA_ID,
    FL3_FITNESS_REGION_SCHEMA_VERSION_HASH,
    validate_fl3_fitness_region,
)
from schemas.fl3_immune_snapshot_schema import (
    FL3_IMMUNE_SNAPSHOT_SCHEMA_ID,
    FL3_IMMUNE_SNAPSHOT_SCHEMA_VERSION_HASH,
    validate_fl3_immune_snapshot,
)
from schemas.fl3_meta_evaluator_receipt_schema import (
    FL3_META_EVALUATOR_RECEIPT_SCHEMA_ID,
    FL3_META_EVALUATOR_RECEIPT_SCHEMA_VERSION_HASH,
    validate_fl3_meta_evaluator_receipt,
)
from schemas.fl3_anchor_reference_set_schema import (
    FL3_ANCHOR_REFERENCE_SET_SCHEMA_ID,
    FL3_ANCHOR_REFERENCE_SET_SCHEMA_VERSION_HASH,
    validate_fl3_anchor_reference_set,
)
from schemas.fl3_adapter_role_spec_v2_schema import (
    FL3_ADAPTER_ROLE_SPEC_V2_SCHEMA_ID,
    FL3_ADAPTER_ROLE_SPEC_V2_SCHEMA_VERSION_HASH,
    validate_fl3_adapter_role_spec_v2,
)
from schemas.fl3_policy_bundle_schema import (
    FL3_POLICY_BUNDLE_SCHEMA_ID,
    FL3_POLICY_BUNDLE_SCHEMA_VERSION_HASH,
    validate_fl3_policy_bundle,
)
from schemas.fl3_hash_manifest_schema import (
    FL3_HASH_MANIFEST_SCHEMA_ID,
    FL3_HASH_MANIFEST_SCHEMA_VERSION_HASH,
    validate_fl3_hash_manifest,
)
from schemas.fl3_supported_platforms_schema import (
    FL3_SUPPORTED_PLATFORMS_SCHEMA_ID,
    FL3_SUPPORTED_PLATFORMS_SCHEMA_VERSION_HASH,
    validate_fl3_supported_platforms,
)
from schemas.fl3_env_lock_schema import (
    FL3_ENV_LOCK_SCHEMA_ID,
    FL3_ENV_LOCK_SCHEMA_VERSION_HASH,
    validate_fl3_env_lock,
)
from schemas.fl3_metabolism_proof_schema import (
    FL3_METABOLISM_PROOF_SCHEMA_ID,
    FL3_METABOLISM_PROOF_SCHEMA_VERSION_HASH,
    validate_fl3_metabolism_proof,
)
from schemas.fl3_determinism_contract_schema import (
    FL3_DETERMINISM_CONTRACT_SCHEMA_ID,
    FL3_DETERMINISM_CONTRACT_SCHEMA_VERSION_HASH,
    validate_fl3_determinism_contract,
)
from schemas.fl3_canary_artifact_schema import (
    FL3_CANARY_ARTIFACT_SCHEMA_ID,
    FL3_CANARY_ARTIFACT_SCHEMA_VERSION_HASH,
    validate_fl3_canary_artifact,
)
from schemas.fl3_utility_pack_manifest_schema import (
    FL3_UTILITY_PACK_MANIFEST_SCHEMA_ID,
    FL3_UTILITY_PACK_MANIFEST_SCHEMA_VERSION_HASH,
    validate_fl3_utility_pack_manifest,
)
from schemas.fl3_scoring_spec_schema import (
    FL3_SCORING_SPEC_SCHEMA_ID,
    FL3_SCORING_SPEC_SCHEMA_VERSION_HASH,
    validate_fl3_scoring_spec,
)
from schemas.fl3_promoted_manifest_schema import (
    FL3_PROMOTED_MANIFEST_SCHEMA_ID,
    FL3_PROMOTED_MANIFEST_SCHEMA_VERSION_HASH,
    validate_fl3_promoted_manifest,
)
from schemas.fl3_promoted_index_schema import (
    FL3_PROMOTED_INDEX_SCHEMA_ID,
    FL3_PROMOTED_INDEX_SCHEMA_VERSION_HASH,
    validate_fl3_promoted_index,
)
from schemas.fl3_discovery_battery_schema import (
    FL3_DISCOVERY_BATTERY_SCHEMA_ID,
    FL3_DISCOVERY_BATTERY_SCHEMA_VERSION_HASH,
    validate_fl3_discovery_battery,
)
from schemas.fl3_discovery_battery_result_schema import (
    FL3_DISCOVERY_BATTERY_RESULT_SCHEMA_ID,
    FL3_DISCOVERY_BATTERY_RESULT_SCHEMA_VERSION_HASH,
    validate_fl3_discovery_battery_result,
)
from schemas.fl3_cognitive_fitness_v2_schema import (
    FL3_COGNITIVE_FITNESS_V2_SCHEMA_ID,
    FL3_COGNITIVE_FITNESS_V2_SCHEMA_VERSION_HASH,
    validate_fl3_cognitive_fitness_v2,
)
from schemas.fl3_cognitive_fitness_policy_schema import (
    FL3_COGNITIVE_FITNESS_POLICY_SCHEMA_ID,
    FL3_COGNITIVE_FITNESS_POLICY_SCHEMA_VERSION_HASH,
    validate_fl3_cognitive_fitness_policy,
)
from schemas.fl3_discovery_case_schema import (
    FL3_DISCOVERY_CASE_SCHEMA_ID,
    FL3_DISCOVERY_CASE_SCHEMA_VERSION_HASH,
    validate_fl3_discovery_case,
)
from schemas.fl3_paradox_event_schema import (
    FL3_PARADOX_EVENT_SCHEMA_ID,
    FL3_PARADOX_EVENT_SCHEMA_VERSION_HASH,
    validate_fl3_paradox_event,
)
from schemas.fl3_schema_violation_schema import (
    FL3_SCHEMA_VIOLATION_SCHEMA_ID,
    FL3_SCHEMA_VIOLATION_SCHEMA_VERSION_HASH,
    validate_fl3_schema_violation,
)
from schemas.fl3_shadow_adapter_manifest_schema import (
    FL3_SHADOW_ADAPTER_MANIFEST_SCHEMA_ID,
    FL3_SHADOW_ADAPTER_MANIFEST_SCHEMA_VERSION_HASH,
    validate_fl3_shadow_adapter_manifest,
)
from schemas.fl3_temporal_lineage_graph_schema import (
    FL3_TEMPORAL_LINEAGE_GRAPH_SCHEMA_ID,
    FL3_TEMPORAL_LINEAGE_GRAPH_SCHEMA_VERSION_HASH,
    validate_fl3_temporal_lineage_graph,
)
from schemas.fl3_trace_violation_schema import (
    FL3_TRACE_VIOLATION_SCHEMA_ID,
    FL3_TRACE_VIOLATION_SCHEMA_VERSION_HASH,
    validate_fl3_trace_violation,
)
from schemas.fl4_preflight_summary_schema import (
    FL4_PREFLIGHT_SUMMARY_SCHEMA_ID,
    FL4_PREFLIGHT_SUMMARY_SCHEMA_VERSION_HASH,
    validate_fl4_preflight_summary,
)
from schemas.fl4_promotion_report_schema import (
    FL4_PROMOTION_REPORT_SCHEMA_ID,
    FL4_PROMOTION_REPORT_SCHEMA_VERSION_HASH,
    validate_fl4_promotion_report,
)
from schemas.phase1c_work_order_schema import (
    PHASE1C_WORK_ORDER_SCHEMA_ID,
    PHASE1C_WORK_ORDER_SCHEMA_VERSION_HASH,
    validate_phase1c_work_order,
)
from schemas.phase2_work_order_schema import (
    PHASE2_WORK_ORDER_SCHEMA_ID,
    PHASE2_WORK_ORDER_SCHEMA_VERSION_HASH,
    validate_phase2_work_order,
)
from schemas.phase2_train_request_schema import (
    PHASE2_TRAIN_REQUEST_SCHEMA_ID,
    PHASE2_TRAIN_REQUEST_SCHEMA_VERSION_HASH,
    validate_phase2_train_request,
)
from schemas.phase2_train_receipt_schema import (
    PHASE2_TRAIN_RECEIPT_SCHEMA_ID,
    PHASE2_TRAIN_RECEIPT_SCHEMA_VERSION_HASH,
    validate_phase2_train_receipt,
)
from schemas.phase2_promotion_receipt_schema import (
    PHASE2_PROMOTION_RECEIPT_SCHEMA_ID,
    PHASE2_PROMOTION_RECEIPT_SCHEMA_VERSION_HASH,
    validate_phase2_promotion_receipt,
)
from schemas.adapter_weight_artifact_manifest_schema import (
    ADAPTER_WEIGHT_ARTIFACT_MANIFEST_SCHEMA_ID,
    ADAPTER_WEIGHT_ARTIFACT_MANIFEST_SCHEMA_VERSION_HASH,
    validate_adapter_weight_artifact_manifest,
)
from schemas.runtime_dag_schema import (
    RUNTIME_DAG_SCHEMA_ID,
    RUNTIME_DAG_SCHEMA_VERSION_HASH,
    validate_runtime_dag,
)
from schemas.judge_receipt_schema import (
    JUDGE_RECEIPT_SCHEMA_ID,
    JUDGE_RECEIPT_SCHEMA_VERSION_HASH,
    validate_judge_receipt,
)
from schemas.schema_files import schema_version_hash


_Validator = Callable[[Dict[str, Any]], None]


def _lazy_validator(module_name: str, validator_attr: str) -> _Validator:
    # Runtime purity: schema_registry is imported in the canonical runtime entrypoint.
    # Avoid importing training-signature schema modules unless their schema_id is actually validated.
    def _v(obj: Dict[str, Any]) -> None:
        mod = importlib.import_module(module_name)
        fn = getattr(mod, validator_attr)
        fn(obj)

    return _v


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
    FL3_FACTORY_JOBSPEC_V2_SCHEMA_ID: (FL3_FACTORY_JOBSPEC_V2_SCHEMA_VERSION_HASH, validate_fl3_factory_jobspec_v2),
    # Lazy import: module name contains "dataset" and will trip runtime purity checks if loaded eagerly.
    "kt.factory.dataset.v1": (
        schema_version_hash("fl3/kt.factory.dataset.v1.json"),
        _lazy_validator("schemas.fl3_factory_dataset_schema", "validate_fl3_factory_dataset"),
    ),
    FL3_FACTORY_JUDGEMENT_SCHEMA_ID: (FL3_FACTORY_JUDGEMENT_SCHEMA_VERSION_HASH, validate_fl3_factory_judgement),
    FL3_FACTORY_TRAIN_MANIFEST_SCHEMA_ID: (
        FL3_FACTORY_TRAIN_MANIFEST_SCHEMA_VERSION_HASH,
        validate_fl3_factory_train_manifest,
    ),
    FL3_FACTORY_EVAL_REPORT_SCHEMA_ID: (FL3_FACTORY_EVAL_REPORT_SCHEMA_VERSION_HASH, validate_fl3_factory_eval_report),
    FL3_FACTORY_EVAL_REPORT_V2_SCHEMA_ID: (
        FL3_FACTORY_EVAL_REPORT_V2_SCHEMA_VERSION_HASH,
        validate_fl3_factory_eval_report_v2,
    ),
    FL3_FACTORY_JOB_DIR_MANIFEST_SCHEMA_ID: (
        FL3_FACTORY_JOB_DIR_MANIFEST_SCHEMA_VERSION_HASH,
        validate_fl3_factory_job_dir_manifest,
    ),
    FL3_FACTORY_PHASE_TRACE_SCHEMA_ID: (
        FL3_FACTORY_PHASE_TRACE_SCHEMA_VERSION_HASH,
        validate_fl3_factory_phase_trace,
    ),
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
    # FL3 addendum-derived artifacts (append-only).
    FL3_FITNESS_POLICY_SCHEMA_ID: (FL3_FITNESS_POLICY_SCHEMA_VERSION_HASH, validate_fl3_fitness_policy),
    FL3_IMMUNE_SNAPSHOT_SCHEMA_ID: (FL3_IMMUNE_SNAPSHOT_SCHEMA_VERSION_HASH, validate_fl3_immune_snapshot),
    FL3_EPIGENETIC_SUMMARY_SCHEMA_ID: (FL3_EPIGENETIC_SUMMARY_SCHEMA_VERSION_HASH, validate_fl3_epigenetic_summary),
    FL3_FITNESS_REGION_SCHEMA_ID: (FL3_FITNESS_REGION_SCHEMA_VERSION_HASH, validate_fl3_fitness_region),
    FL3_SHADOW_ADAPTER_MANIFEST_SCHEMA_ID: (
        FL3_SHADOW_ADAPTER_MANIFEST_SCHEMA_VERSION_HASH,
        validate_fl3_shadow_adapter_manifest,
    ),
    FL3_BREEDING_MANIFEST_SCHEMA_ID: (FL3_BREEDING_MANIFEST_SCHEMA_VERSION_HASH, validate_fl3_breeding_manifest),
    FL3_TRACE_VIOLATION_SCHEMA_ID: (FL3_TRACE_VIOLATION_SCHEMA_VERSION_HASH, validate_fl3_trace_violation),
    FL3_SCHEMA_VIOLATION_SCHEMA_ID: (FL3_SCHEMA_VIOLATION_SCHEMA_VERSION_HASH, validate_fl3_schema_violation),
    FL3_PARADOX_EVENT_SCHEMA_ID: (FL3_PARADOX_EVENT_SCHEMA_VERSION_HASH, validate_fl3_paradox_event),
    FL3_TEMPORAL_LINEAGE_GRAPH_SCHEMA_ID: (
        FL3_TEMPORAL_LINEAGE_GRAPH_SCHEMA_VERSION_HASH,
        validate_fl3_temporal_lineage_graph,
    ),
    FL3_META_EVALUATOR_RECEIPT_SCHEMA_ID: (
        FL3_META_EVALUATOR_RECEIPT_SCHEMA_VERSION_HASH,
        validate_fl3_meta_evaluator_receipt,
    ),
    # FL4: meaning governance kernel (append-only).
    FL3_POLICY_BUNDLE_SCHEMA_ID: (FL3_POLICY_BUNDLE_SCHEMA_VERSION_HASH, validate_fl3_policy_bundle),
    FL3_HASH_MANIFEST_SCHEMA_ID: (FL3_HASH_MANIFEST_SCHEMA_VERSION_HASH, validate_fl3_hash_manifest),
    FL3_SUPPORTED_PLATFORMS_SCHEMA_ID: (FL3_SUPPORTED_PLATFORMS_SCHEMA_VERSION_HASH, validate_fl3_supported_platforms),
    FL3_ENV_LOCK_SCHEMA_ID: (FL3_ENV_LOCK_SCHEMA_VERSION_HASH, validate_fl3_env_lock),
    FL3_METABOLISM_PROOF_SCHEMA_ID: (FL3_METABOLISM_PROOF_SCHEMA_VERSION_HASH, validate_fl3_metabolism_proof),
    FL3_DETERMINISM_CONTRACT_SCHEMA_ID: (
        FL3_DETERMINISM_CONTRACT_SCHEMA_VERSION_HASH,
        validate_fl3_determinism_contract,
    ),
    FL3_CANARY_ARTIFACT_SCHEMA_ID: (FL3_CANARY_ARTIFACT_SCHEMA_VERSION_HASH, validate_fl3_canary_artifact),
    FL3_UTILITY_PACK_MANIFEST_SCHEMA_ID: (
        FL3_UTILITY_PACK_MANIFEST_SCHEMA_VERSION_HASH,
        validate_fl3_utility_pack_manifest,
    ),
    FL3_SCORING_SPEC_SCHEMA_ID: (FL3_SCORING_SPEC_SCHEMA_VERSION_HASH, validate_fl3_scoring_spec),
    FL3_PROMOTED_MANIFEST_SCHEMA_ID: (FL3_PROMOTED_MANIFEST_SCHEMA_VERSION_HASH, validate_fl3_promoted_manifest),
    FL3_PROMOTED_INDEX_SCHEMA_ID: (FL3_PROMOTED_INDEX_SCHEMA_VERSION_HASH, validate_fl3_promoted_index),
    # FL4: preflight/promotion reports (append-only).
    FL4_PREFLIGHT_SUMMARY_SCHEMA_ID: (FL4_PREFLIGHT_SUMMARY_SCHEMA_VERSION_HASH, validate_fl4_preflight_summary),
    FL4_PROMOTION_REPORT_SCHEMA_ID: (FL4_PROMOTION_REPORT_SCHEMA_VERSION_HASH, validate_fl4_promotion_report),
    # Phase 1C: work order (append-only).
    PHASE1C_WORK_ORDER_SCHEMA_ID: (PHASE1C_WORK_ORDER_SCHEMA_VERSION_HASH, validate_phase1c_work_order),
    # Phase 2: governed learning unlock work order (append-only; policy artifact).
    PHASE2_WORK_ORDER_SCHEMA_ID: (PHASE2_WORK_ORDER_SCHEMA_VERSION_HASH, validate_phase2_work_order),
    # Phase 2: governed training request/receipt (append-only; MRT-1 weight-bearing lane).
    PHASE2_TRAIN_REQUEST_SCHEMA_ID: (PHASE2_TRAIN_REQUEST_SCHEMA_VERSION_HASH, validate_phase2_train_request),
    PHASE2_TRAIN_RECEIPT_SCHEMA_ID: (PHASE2_TRAIN_RECEIPT_SCHEMA_VERSION_HASH, validate_phase2_train_receipt),
    PHASE2_PROMOTION_RECEIPT_SCHEMA_ID: (PHASE2_PROMOTION_RECEIPT_SCHEMA_VERSION_HASH, validate_phase2_promotion_receipt),
    ADAPTER_WEIGHT_ARTIFACT_MANIFEST_SCHEMA_ID: (
        ADAPTER_WEIGHT_ARTIFACT_MANIFEST_SCHEMA_VERSION_HASH,
        validate_adapter_weight_artifact_manifest,
    ),
    # Phase 1C: runtime instantiation artifacts (append-only).
    RUNTIME_DAG_SCHEMA_ID: (RUNTIME_DAG_SCHEMA_VERSION_HASH, validate_runtime_dag),
    JUDGE_RECEIPT_SCHEMA_ID: (JUDGE_RECEIPT_SCHEMA_VERSION_HASH, validate_judge_receipt),
    # FL3.2: cognitive fitness + discovery battery (append-only).
    FL3_ANCHOR_REFERENCE_SET_SCHEMA_ID: (
        FL3_ANCHOR_REFERENCE_SET_SCHEMA_VERSION_HASH,
        validate_fl3_anchor_reference_set,
    ),
    FL3_ADAPTER_ROLE_SPEC_V2_SCHEMA_ID: (
        FL3_ADAPTER_ROLE_SPEC_V2_SCHEMA_VERSION_HASH,
        validate_fl3_adapter_role_spec_v2,
    ),
    FL3_DISCOVERY_CASE_SCHEMA_ID: (
        FL3_DISCOVERY_CASE_SCHEMA_VERSION_HASH,
        validate_fl3_discovery_case,
    ),
    FL3_DISCOVERY_BATTERY_SCHEMA_ID: (
        FL3_DISCOVERY_BATTERY_SCHEMA_VERSION_HASH,
        validate_fl3_discovery_battery,
    ),
    FL3_DISCOVERY_BATTERY_RESULT_SCHEMA_ID: (
        FL3_DISCOVERY_BATTERY_RESULT_SCHEMA_VERSION_HASH,
        validate_fl3_discovery_battery_result,
    ),
    FL3_COGNITIVE_FITNESS_POLICY_SCHEMA_ID: (
        FL3_COGNITIVE_FITNESS_POLICY_SCHEMA_VERSION_HASH,
        validate_fl3_cognitive_fitness_policy,
    ),
    FL3_COGNITIVE_FITNESS_V2_SCHEMA_ID: (
        FL3_COGNITIVE_FITNESS_V2_SCHEMA_VERSION_HASH,
        validate_fl3_cognitive_fitness_v2,
    ),
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
