from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator import run_bounded_forward_streams
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable


PROGRAM_ID = "KT_LOBE_ADAPTER_ROUTER_GPU_CONVERSION_STAGING_SUPERLANE_V1"
CURRENT_POSTURE = "KT_NEAR_FINAL_SHADOW_COMPLETE__BOUNDED_LAUNCH_WEDGE_READY__EXTERNAL_ATTESTATION_AND_EXTERNAL_BENCHMARKING_PENDING"
TARGET_OUTCOME = "KT_LOBE_ADAPTER_ROUTER_GPU_CONVERSION_READY__TRAINING_EXECUTION_PENDING__CLAIM_CEILING_PRESERVED"

BLOCKED_CLAIMS = {
    "external_audit_accepted": False,
    "external_audit_complete": False,
    "commercial_claim_authorized": False,
    "seven_b_amplification_proven": False,
    "category_leadership_claim_authorized": False,
    "beyond_sota_claim_authorized": False,
    "full_adaptive_orchestration_production_ready": False,
    "truth_engine_law_changed": False,
    "trust_zone_law_changed": False,
}

LIVE_INPUTS = {
    "near_final_shadow_readjudication": "KT_PROD_CLEANROOM/reports/kt_near_final_shadow_readjudication_receipt.json",
    "near_final_shadow_execution_board": "KT_PROD_CLEANROOM/reports/kt_near_final_shadow_execution_board.json",
    "claim_boundary": "KT_PROD_CLEANROOM/reports/kt_final_claim_boundary_before_external_attestation.json",
    "remaining_external_blockers": "KT_PROD_CLEANROOM/reports/kt_remaining_external_blockers.json",
    "training_eval_fabric": "KT_PROD_CLEANROOM/reports/training_eval_fabric_shadow_ready_receipt.json",
    "benchmark_harness": "KT_PROD_CLEANROOM/reports/benchmark_harness_internal_dry_run_receipt.json",
    "capability_status_board": "KT_PROD_CLEANROOM/reports/kt_shadow_capability_status_board.json",
    "fp0_receipt": "KT_PROD_CLEANROOM/reports/fp0_runtime_state_context_efficiency_activation_receipt.json",
    "router_policy": "adaptive/router_policy_registry.json",
    "router_shadow_eval": "adaptive/router_shadow_eval_matrix.json",
    "adapter_registry": "adaptive/adapter_registry.json",
    "adapter_lineage": "adaptive/adapter_lineage_manifest.json",
    "lobe_role_registry": "adaptive/lobe_role_registry.json",
    "tournament_protocol": "adaptive/tournament_protocol.json",
    "rollback_schema": "adaptive/rollback_receipt.schema.json",
    "quarantine_schema": "adaptive/quarantine_receipt.schema.json",
    "dataset_manifest_schema": "training/dataset_manifest.schema.json",
    "model_provenance_schema": "training/model_provenance.schema.json",
    "adapter_training_manifest_schema": "training/adapter_training_manifest.schema.json",
    "training_authorization_schema": "training/training_authorization_packet.schema.json",
    "training_run_receipt_schema": "training/training_run_receipt.schema.json",
    "training_rollback_schema": "training/rollback_plan.schema.json",
    "eval_receipt_schema": "eval/eval_receipt.schema.json",
    "negative_result_ledger": "eval/negative_result_ledger.json",
    "benchmark_constitution": "evals/benchmark_constitution.yaml",
    "baseline_registry": "evals/baseline_registry.json",
    "comparative_scorecard": "evals/comparative_scorecard.json",
    "monolith_adapter_router_matrix": "evals/monolith_vs_adapter_vs_router_matrix.json",
    "provider_bakeoff_scorecard": "evals/provider_runtime_bakeoff_scorecard.json",
    "context_pack_policy": "context_packing/context_pack_policy.yaml",
    "context_pack_benchmark": "context_packing/context_pack_benchmark.py",
    "kaggle_hypertraining_packet": "KT_PROD_CLEANROOM/reports/cohort0_targeted_hypertraining_kaggle_packet.json",
    "kaggle_import_receipt": "KT_PROD_CLEANROOM/reports/cohort0_targeted_hypertraining_import_receipt.json",
    "b04_r6_candidate_provenance": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_provenance_matrix.json",
    "b04_r6_comparator_contract": "KT_PROD_CLEANROOM/reports/b04_r6_comparator_matrix_contract.json",
    "b04_r6_shadow_screen_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_superiority_screen_receipt.json",
}

STALE_OR_PREP_ONLY_INPUTS = {
    "canary_era_lobe_abi_prep": "KT_PROD_CLEANROOM/reports/kt_lobe_abi_contract_prep_only.json",
    "canary_era_lobe_ratification_factory_prep": "KT_PROD_CLEANROOM/reports/kt_lobe_ratification_factory_contract_prep_only.json",
    "old_gpu_training_readiness_gate": "KT_PROD_CLEANROOM/reports/kt_gpu_training_readiness_gate.json",
    "learned_router_activation_review_prep": "KT_PROD_CLEANROOM/reports/b04_r6_learned_router_activation_review_packet_prep_only_draft.json",
    "learned_router_activation_risk_register_prep": "KT_PROD_CLEANROOM/reports/b04_r6_learned_router_activation_risk_register_prep_only_draft.json",
}

OUTPUTS = {
    "cutline": "KT_PROD_CLEANROOM/reports/kt_gpu_conversion_current_head_cutline_manifest.json",
    "classification": "KT_PROD_CLEANROOM/reports/kt_gpu_conversion_artifact_classification.json",
    "lobe_target_matrix": "KT_PROD_CLEANROOM/reports/kt_lobe_target_matrix.json",
    "adapter_target_matrix": "KT_PROD_CLEANROOM/reports/kt_adapter_target_matrix.json",
    "recipe_matrix": "KT_PROD_CLEANROOM/reports/kt_lora_qlora_recipe_matrix.json",
    "dataset_manifest": "KT_PROD_CLEANROOM/reports/kt_gpu_conversion_dataset_provenance_manifest.json",
    "training_authorization": "KT_PROD_CLEANROOM/reports/kt_gpu_training_authorization_scaffold.json",
    "kaggle_packet": "KT_PROD_CLEANROOM/reports/kt_kaggle_gpu_execution_packet.json",
    "checkpoint_policy": "KT_PROD_CLEANROOM/reports/kt_gpu_checkpoint_resume_policy.json",
    "import_contract": "KT_PROD_CLEANROOM/reports/kt_gpu_artifact_import_hash_receipt_contract.json",
    "router_plan": "KT_PROD_CLEANROOM/reports/kt_router_candidate_generation_plan.json",
    "static_baseline": "KT_PROD_CLEANROOM/reports/kt_static_baseline_binding.json",
    "benchmark_gate": "KT_PROD_CLEANROOM/reports/kt_gpu_benchmark_eval_gate_contract.json",
    "rollback_policy": "KT_PROD_CLEANROOM/reports/kt_gpu_conversion_rollback_quarantine_policy.json",
    "negative_schema": "eval/kt_gpu_conversion_negative_result_ledger.schema.json",
    "claim_receipt": "KT_PROD_CLEANROOM/reports/kt_gpu_conversion_claim_ceiling_preservation_receipt.json",
    "runbook": "training/kaggle_gpu_conversion_runbook.md",
    "staging_receipt": "KT_PROD_CLEANROOM/reports/kt_lobe_adapter_router_gpu_conversion_staging_receipt.json",
    "execution_board": "KT_PROD_CLEANROOM/reports/kt_lobe_adapter_router_gpu_conversion_execution_board.json",
}

HUMAN_CLAIM_SCAN_OUTPUTS = ("runbook",)

KAGGLE_REQUIRED_OUTPUTS = (
    "dataset_manifest.json",
    "training_config.json",
    "checkpoint_manifest.json",
    "training_run_receipt.json",
    "eval_receipt.json",
    "router_trace.csv",
    "candidate_provenance.json",
    "negative_result_ledger.json",
)

KAGGLE_OUTPUT_HASH_FIELDS = {
    "dataset_manifest.json": "dataset_manifest_hash",
    "training_config.json": "training_config_hash",
    "checkpoint_manifest.json": "checkpoint_manifest_hash",
    "training_run_receipt.json": "training_run_receipt_hash",
    "eval_receipt.json": "eval_receipt_hash",
    "router_trace.csv": "router_trace_csv_hash",
    "candidate_provenance.json": "candidate_provenance_hash",
    "negative_result_ledger.json": "negative_result_ledger_hash",
}


def _load_json(path: Path) -> Dict[str, Any]:
    return load_json(path)


def _write_text_stable(path: Path, text: str) -> bool:
    normalized = text.replace("\r\n", "\n")
    if not normalized.endswith("\n"):
        normalized += "\n"
    if path.exists() and path.read_text(encoding="utf-8-sig").replace("\r\n", "\n") == normalized:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(normalized, encoding="utf-8", newline="\n")
    return True


def _git_head(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except Exception:  # noqa: BLE001
        return "UNKNOWN_NON_GIT_TEST_ROOT"


def _hash_entry(root: Path, raw: str) -> Dict[str, Any]:
    path = root / raw
    return {
        "path": raw,
        "exists": path.is_file(),
        "sha256": file_sha256(path) if path.is_file() else "",
    }


def _required_live_entries(root: Path) -> list[Dict[str, Any]]:
    return [
        {
            "role": role,
            "authority": "LIVE_CURRENT_HEAD_INPUT",
            "classification": "LIVE",
            **_hash_entry(root, raw),
        }
        for role, raw in LIVE_INPUTS.items()
    ]


def _stale_entries(root: Path) -> list[Dict[str, Any]]:
    return [
        {
            "role": role,
            "classification": "STALE_OR_PREP_ONLY_NOT_CONTROLLING_GPU_CAMPAIGN",
            "controls_gpu_campaign": False,
            "reason": "May inform design only after explicit re-binding in the current-head GPU conversion packet.",
            **_hash_entry(root, raw),
        }
        for role, raw in STALE_OR_PREP_ONLY_INPUTS.items()
    ]


def _assert_claim_boundary(root: Path) -> None:
    receipts = [
        _load_json(root / LIVE_INPUTS["near_final_shadow_readjudication"]),
        _load_json(root / LIVE_INPUTS["claim_boundary"]),
    ]
    for receipt in receipts:
        for key, expected in BLOCKED_CLAIMS.items():
            if receipt.get(key) is not expected:
                raise RuntimeError(f"Claim boundary drift: expected {key}={expected} in {receipt.get('artifact_id', receipt.get('schema_id'))}")
    router_policy = _load_json(root / LIVE_INPUTS["router_policy"])
    if router_policy.get("learned_router_claim_allowed") is not False:
        raise RuntimeError("Router policy drift: learned-router claim must remain false.")
    training_gate = _load_json(root / LIVE_INPUTS["training_eval_fabric"])
    if training_gate.get("training_without_authorization_allowed") is not False:
        raise RuntimeError("Training gate drift: training without authorization must remain false.")
    if training_gate.get("dataset_without_provenance_allowed") is not False:
        raise RuntimeError("Training gate drift: dataset without provenance must remain false.")


def _cutline(root: Path, current_head: str) -> Dict[str, Any]:
    live = _required_live_entries(root)
    missing = [entry for entry in live if not entry["exists"]]
    return {
        "schema_id": "kt.gpu_conversion.current_head_cutline_manifest.v1",
        "artifact_id": "KT_GPU_CONVERSION_CURRENT_HEAD_CUTLINE_MANIFEST",
        "program_id": PROGRAM_ID,
        "generated_utc": utc_now_iso_z(),
        "current_head": current_head,
        "current_head_binding_semantics": "pre-staging live-input git head; generated GPU conversion artifacts are expected to be committed after this cutline",
        "artifact_commit_expected_after_write": "PENDING_COMMIT_OR_PR_HEAD",
        "validation_must_recompute_live_input_hashes": True,
        "current_posture": CURRENT_POSTURE,
        "target_outcome": TARGET_OUTCOME,
        "live_inputs": live,
        "missing_live_input_count": len(missing),
        "missing_live_inputs": missing,
        "stale_or_prep_only_inputs": _stale_entries(root),
        "stale_inputs_control_gpu_campaign": False,
        "full_gpu_training_executed": False,
        **BLOCKED_CLAIMS,
    }


def _classification(root: Path) -> Dict[str, Any]:
    return {
        "schema_id": "kt.gpu_conversion.artifact_classification.v1",
        "artifact_id": "KT_GPU_CONVERSION_ARTIFACT_CLASSIFICATION",
        "authority": "CURRENT_HEAD_CUTLINE_ONLY",
        "generated_utc": utc_now_iso_z(),
        "classes": {
            "LIVE_INPUT": sorted(LIVE_INPUTS.values()),
            "STALE_OR_PREP_ONLY_NOT_CONTROLLING": sorted(STALE_OR_PREP_ONLY_INPUTS.values()),
            "TRAINING_EXECUTABLE_AFTER_THIS_PACKET": [
                OUTPUTS["lobe_target_matrix"],
                OUTPUTS["adapter_target_matrix"],
                OUTPUTS["recipe_matrix"],
                OUTPUTS["dataset_manifest"],
                OUTPUTS["training_authorization"],
                OUTPUTS["kaggle_packet"],
                OUTPUTS["checkpoint_policy"],
                OUTPUTS["import_contract"],
                OUTPUTS["benchmark_gate"],
            ],
            "EVIDENCE_IMPORT_REQUIRED_AFTER_GPU": [
                "candidate_provenance.json",
                "training_run_receipt.json",
                "checkpoint_manifest.json",
                "eval_receipt.json",
                "router_trace.csv",
                "negative_result_ledger.json",
            ],
        },
        "stale_b04_r6_canary_blockers_control_gpu_campaign": False,
        "branch_bound_artifacts_control_gpu_campaign": False,
        **BLOCKED_CLAIMS,
    }


def _lobe_targets() -> Dict[str, Any]:
    lobes = [
        ("routing_control_lobe", ["route_selection", "abstention_static_hold"], "router_candidate_generation"),
        ("evidence_auditor_lobe", ["trace_completeness", "provenance_integrity"], "eval_receipt_review"),
        ("claim_boundary_lobe", ["claim_scan", "forbidden_claim_detection"], "claim_ceiling_preservation"),
        ("benchmark_eval_lobe", ["baseline_comparison", "negative_result_retention"], "benchmark_gate"),
        ("context_efficiency_lobe", ["context_pack_selection", "cache_budgeting"], "fp0_no_claim_expansion"),
        ("rollback_quarantine_lobe", ["rollback_plan", "quarantine_decision"], "failure_handling"),
    ]
    return {
        "schema_id": "kt.gpu_conversion.lobe_target_matrix.v1",
        "artifact_id": "KT_LOBE_TARGET_MATRIX",
        "authority": "TRAINING_STAGING_ONLY",
        "generated_utc": utc_now_iso_z(),
        "lobes": [
            {
                "lobe_id": lobe_id,
                "sub_lobes": sub_lobes,
                "objective": objective,
                "trainable_surface": "adapter_or_router_head_only",
                "requires_dataset_provenance": True,
                "requires_recipe": True,
                "requires_eval_gate": True,
                "requires_rollback": True,
                "requires_receipt": True,
                "production_authority_after_training": False,
            }
            for lobe_id, sub_lobes, objective in lobes
        ],
        **BLOCKED_CLAIMS,
    }


def _adapter_targets() -> Dict[str, Any]:
    adapters = [
        ("route_selector_adapter", "routing_control_lobe", "rank route options without activation"),
        ("abstention_static_hold_adapter", "routing_control_lobe", "prefer static hold when confidence is weak"),
        ("evidence_trace_adapter", "evidence_auditor_lobe", "emit complete route/provenance traces"),
        ("claim_ceiling_adapter", "claim_boundary_lobe", "detect claim drift in generated outputs"),
        ("benchmark_judge_adapter", "benchmark_eval_lobe", "score benchmark outcomes under frozen rubric"),
        ("context_packing_adapter", "context_efficiency_lobe", "select compact context representation while JSON remains canonical"),
        ("rollback_quarantine_adapter", "rollback_quarantine_lobe", "classify rollback or quarantine paths"),
    ]
    return {
        "schema_id": "kt.gpu_conversion.adapter_target_matrix.v1",
        "artifact_id": "KT_ADAPTER_TARGET_MATRIX",
        "authority": "TRAINING_STAGING_ONLY",
        "generated_utc": utc_now_iso_z(),
        "adapters": [
            {
                "adapter_id": adapter_id,
                "parent_lobe": parent_lobe,
                "objective": objective,
                "default_recipe": "LORA_SMOKE_V1",
                "optional_recipe": "QLORA_MEMORY_GATED_V1",
                "requires_lineage_manifest": True,
                "requires_eval_receipt": True,
                "requires_tournament_entry_receipt": True,
                "requires_rollback_plan": True,
                "promotion_authorized_by_this_packet": False,
            }
            for adapter_id, parent_lobe, objective in adapters
        ],
        **BLOCKED_CLAIMS,
    }


def _recipe_matrix() -> Dict[str, Any]:
    return {
        "schema_id": "kt.gpu_conversion.lora_qlora_recipe_matrix.v1",
        "artifact_id": "KT_LORA_QLORA_RECIPE_MATRIX",
        "authority": "TRAINING_RECIPE_STAGING_ONLY",
        "generated_utc": utc_now_iso_z(),
        "recipes": [
            {
                "recipe_id": "LORA_SMOKE_V1",
                "method": "LoRA",
                "first_campaign_status": "INCLUDED",
                "base_model_policy": "small_open_model_or_cached_hf_model_only",
                "rank": 8,
                "alpha": 16,
                "dropout": 0.05,
                "max_steps_default": 120,
                "requires_gpu": False,
                "requires_dataset_provenance": True,
                "requires_checkpoint_manifest": True,
                "requires_eval_receipt": True,
            },
            {
                "recipe_id": "QLORA_MEMORY_GATED_V1",
                "method": "QLoRA",
                "first_campaign_status": "STAGED_WITH_SMOKE_TEST_NOT_REQUIRED_FOR_FIRST_PASS",
                "base_model_policy": "only if bitsandbytes and GPU memory smoke pass",
                "quantization": "4bit_nf4",
                "rank": 8,
                "alpha": 16,
                "dropout": 0.05,
                "requires_bitsandbytes_smoke_test": True,
                "requires_gpu_memory_receipt": True,
                "fallback_recipe": "LORA_SMOKE_V1",
                "exclusion_if_smoke_fails": "EXCLUDE_QLORA_FROM_FIRST_CAMPAIGN_WITH_RECEIPT",
            },
        ],
        "qlora_either_staged_with_tests_or_excluded": True,
        **BLOCKED_CLAIMS,
    }


def _dataset_manifest() -> Dict[str, Any]:
    datasets = [
        {
            "dataset_id": "router_admissibility_smoke_public",
            "source": "Hugging Face public dataset or cached mirror",
            "purpose": "minimal router candidate smoke",
            "train_allowed_after_authorization": True,
            "requires_license_record": True,
            "requires_split_hash": True,
            "requires_input_hashes": True,
            "blocks_training_if_missing": True,
        },
        {
            "dataset_id": "kt_trace_claim_boundary_internal",
            "source": "KT generated trace/claim fixtures",
            "purpose": "claim-boundary and trace-completeness adapter evaluation",
            "train_allowed_after_authorization": False,
            "requires_license_record": False,
            "requires_split_hash": True,
            "requires_input_hashes": True,
            "blocks_training_if_missing": True,
        },
        {
            "dataset_id": "benchmark_dry_run_holdout",
            "source": "frozen benchmark holdout manifest",
            "purpose": "evaluation only",
            "train_allowed_after_authorization": False,
            "requires_license_record": True,
            "requires_split_hash": True,
            "requires_input_hashes": True,
            "blocks_training_if_missing": True,
        },
    ]
    return {
        "schema_id": "kt.gpu_conversion.dataset_provenance_manifest.v1",
        "artifact_id": "KT_GPU_CONVERSION_DATASET_PROVENANCE_MANIFEST",
        "authority": "DATASET_PROVENANCE_STAGING_ONLY",
        "generated_utc": utc_now_iso_z(),
        "datasets": datasets,
        "dataset_without_provenance_allowed": False,
        "training_without_dataset_manifest_allowed": False,
        **BLOCKED_CLAIMS,
    }


def _training_authorization() -> Dict[str, Any]:
    return {
        "schema_id": "kt.gpu_conversion.training_authorization_scaffold.v1",
        "artifact_id": "KT_GPU_TRAINING_AUTHORIZATION_SCAFFOLD",
        "authority": "AUTHORIZATION_SCAFFOLD_ONLY",
        "generated_utc": utc_now_iso_z(),
        "full_gpu_training_executed": False,
        "full_training_authorized_by_this_packet": False,
        "kaggle_smoke_execution_ready_next": True,
        "kaggle_smoke_is_not_full_training": True,
        "next_lawful_move_after_validation": "RUN_KT_GPU_CONVERSION_KAGGLE_SMOKE",
        "required_before_training": [
            "current-head cutline manifest passes",
            "dataset provenance manifest complete",
            "lobe and adapter targets selected",
            "LoRA/QLoRA recipe selected",
            "checkpoint/resume policy accepted",
            "artifact import contract accepted",
            "claim ceiling preservation receipt passes",
        ],
        **BLOCKED_CLAIMS,
    }


def _kaggle_packet() -> Dict[str, Any]:
    return {
        "schema_id": "kt.gpu_conversion.kaggle_execution_packet.v1",
        "artifact_id": "KT_KAGGLE_GPU_EXECUTION_PACKET",
        "authority": "KAGGLE_EXECUTION_STAGING_ONLY",
        "generated_utc": utc_now_iso_z(),
        "execution_mode": "SMOKE_FIRST_THEN_INCREMENTAL_TRAINING",
        "deterministic_seed": 1337,
        "run_id_format": "kt_gpu_conversion_{utc_timestamp}_{short_uuid}",
        "default_working_dir": "/kaggle/working/kt_gpu_conversion",
        "cache_policy": {
            "hf_home": "/kaggle/working/hf_cache",
            "local_artifact_cache": "/kaggle/working/kt_gpu_conversion/cache",
            "resume_manifest": "/kaggle/working/kt_gpu_conversion/latest_run.json",
            "reuse_cached_hf_downloads": True,
            "network_flaky_mode_supported": True,
        },
        "time_limit_policy": {
            "save_checkpoint_every_steps": 25,
            "early_stop_margin_seconds": 600,
            "partial_results_are_valid_evidence": True,
            "safe_resume_required": True,
        },
        "windows_to_linux_path_note": "Local Windows paths must be copied or mounted into Kaggle input datasets; notebook cells must use /kaggle/input or /kaggle/working paths.",
        "execution_phases": [
            "environment_smoke",
            "dataset_provenance_smoke",
            "lora_smoke",
            "qlora_optional_smoke_if_bitsandbytes_available",
            "router_trace_smoke",
            "artifact_import_hash_smoke",
        ],
        "required_outputs": [
            *KAGGLE_REQUIRED_OUTPUTS,
        ],
        "full_gpu_training_executed": False,
        **BLOCKED_CLAIMS,
    }


def _checkpoint_policy() -> Dict[str, Any]:
    return {
        "schema_id": "kt.gpu_conversion.checkpoint_resume_policy.v1",
        "artifact_id": "KT_GPU_CHECKPOINT_RESUME_POLICY",
        "authority": "RESUME_POLICY",
        "generated_utc": utc_now_iso_z(),
        "idempotent_rerun_required": True,
        "checkpoint_required_before_timeout": True,
        "latest_run_pointer_required": True,
        "partial_result_receipts_required": True,
        "restart_from_scratch_allowed_by_default": False,
        "required_checkpoint_files": ["latest_run.json", "checkpoint_manifest.json", "training_run_receipt.json"],
    }


def _import_contract() -> Dict[str, Any]:
    hash_bindings = [
        {"required_output": output, "hash_field": KAGGLE_OUTPUT_HASH_FIELDS[output]}
        for output in KAGGLE_REQUIRED_OUTPUTS
    ]
    return {
        "schema_id": "kt.gpu_conversion.artifact_import_hash_receipt_contract.v1",
        "artifact_id": "KT_GPU_ARTIFACT_IMPORT_HASH_RECEIPT_CONTRACT",
        "authority": "IMPORT_CONTRACT_BEFORE_EXECUTION",
        "generated_utc": utc_now_iso_z(),
        "import_allowed_only_after_hashing": True,
        "required_hashes": ["sha256"],
        "required_import_fields": [
            "run_id",
            "source_environment",
            *KAGGLE_OUTPUT_HASH_FIELDS.values(),
        ],
        "required_output_hash_bindings": hash_bindings,
        "import_does_not_authorize_claims": True,
        "training_execution_next_not_done": True,
        **BLOCKED_CLAIMS,
    }


def _router_plan() -> Dict[str, Any]:
    return {
        "schema_id": "kt.gpu_conversion.router_candidate_generation_plan.v1",
        "artifact_id": "KT_ROUTER_CANDIDATE_GENERATION_PLAN",
        "authority": "ROUTER_CANDIDATE_PLAN_ONLY",
        "generated_utc": utc_now_iso_z(),
        "candidate_generation_after_gpu_allowed": True,
        "candidate_generation_requires": [
            "source-bound training artifacts",
            "static baseline binding",
            "route decision trace schema",
            "abstention/static-hold policy",
            "no-regression gate",
            "overrouting gate",
            "mirror/masked invariance gate",
        ],
        "learned_router_activation_allowed": False,
        "learned_router_superiority_claim_allowed": False,
        "next_router_gate": "AUTHOR_B04_R6_LEARNED_ROUTER_CANDIDATE_SOURCE_FROM_GPU_ARTIFACTS",
        **BLOCKED_CLAIMS,
    }


def _static_baseline() -> Dict[str, Any]:
    return {
        "schema_id": "kt.gpu_conversion.static_baseline_binding.v1",
        "artifact_id": "KT_STATIC_BASELINE_BINDING",
        "authority": "COMPARATOR_BINDING",
        "generated_utc": utc_now_iso_z(),
        "baseline_required": "best_static_adapter",
        "static_baseline_remains_canonical_until_router_superiority_is_earned": True,
        "router_candidate_must_beat_static_before_claim": True,
        "known_prior_r6_result": {
            "candidate_win_count": 0,
            "case_count": 4,
            "interpretation": "prior candidate did not earn superiority and is diagnostic only unless re-bound",
        },
        **BLOCKED_CLAIMS,
    }


def _benchmark_gate() -> Dict[str, Any]:
    return {
        "schema_id": "kt.gpu_conversion.benchmark_eval_gate_contract.v1",
        "artifact_id": "KT_GPU_BENCHMARK_EVAL_GATE_CONTRACT",
        "authority": "BENCHMARK_GATE_STAGING_ONLY",
        "generated_utc": utc_now_iso_z(),
        "required_metrics": [
            "task_quality",
            "no_regression",
            "route_distribution_health",
            "abstention_quality",
            "overrouting_rate",
            "calibration",
            "cost_per_validated_lane",
            "trace_completeness",
            "replay_success",
        ],
        "required_comparators": ["monolith_only", "best_static_adapter", "routed_adapter_stack"],
        "public_superiority_claim_allowed": False,
        "external_benchmarking_pending": True,
        **BLOCKED_CLAIMS,
    }


def _rollback_policy() -> Dict[str, Any]:
    return {
        "schema_id": "kt.gpu_conversion.rollback_quarantine_policy.v1",
        "artifact_id": "KT_GPU_CONVERSION_ROLLBACK_QUARANTINE_POLICY",
        "authority": "FAILURE_HANDLING_STAGING_ONLY",
        "generated_utc": utc_now_iso_z(),
        "rollback_required_for_every_training_target": True,
        "quarantine_required_for": [
            "missing provenance",
            "checkpoint hash mismatch",
            "eval regression",
            "claim drift",
            "trace incompleteness",
            "benchmark contamination",
        ],
        "negative_results_retained": True,
        "failed_training_can_promote": False,
    }


def _negative_schema() -> Dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "kt.gpu_conversion.negative_result_ledger.v1",
        "title": "KT GPU conversion negative result ledger",
        "type": "object",
        "required": ["schema_id", "run_id", "entries"],
        "additionalProperties": True,
        "properties": {
            "schema_id": {"type": "string"},
            "run_id": {"type": "string"},
            "entries": {"type": "array", "items": {"type": "object"}},
            "claim_expansion_allowed": {"const": False},
        },
    }


def _claim_receipt(current_head: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.gpu_conversion.claim_ceiling_preservation_receipt.v1",
        "artifact_id": "KT_GPU_CONVERSION_CLAIM_CEILING_PRESERVATION_RECEIPT",
        "authority": "CLAIM_CEILING_PRESERVATION",
        "generated_utc": utc_now_iso_z(),
        "current_head": current_head,
        "current_head_binding_semantics": "pre-staging live-input git head; generated GPU conversion artifacts are expected to be committed after this cutline",
        "target_outcome": TARGET_OUTCOME,
        "full_gpu_training_executed": False,
        "trained_weights_claimed": False,
        "gpu_execution_completed": False,
        "training_execution_next": True,
        "external_attestation_pending": True,
        "external_benchmarking_pending": True,
        **BLOCKED_CLAIMS,
    }


def _runbook() -> str:
    return f"""# KT GPU Conversion Kaggle Runbook

Authority: staging only.

This runbook prepares Kaggle execution for lobe, adapter, and router training. It does not claim trained weights exist, router superiority, external audit acceptance, commercial authorization, category leadership, beyond-SOTA status, 7B proof, or full adaptive production readiness.

## Kaggle defaults

```text
RUN_ID=kt_gpu_conversion_<utc_timestamp>_<short_uuid>
SEED=1337
WORK_DIR=/kaggle/working/kt_gpu_conversion
HF_HOME=/kaggle/working/hf_cache
LOCAL_CACHE=/kaggle/working/kt_gpu_conversion/cache
CHECKPOINT_DIR=/kaggle/working/kt_gpu_conversion/checkpoints
LATEST_RUN=/kaggle/working/kt_gpu_conversion/latest_run.json
```

Local Windows paths must be copied or mounted into Kaggle input datasets before execution. Kaggle cells must use `/kaggle/input` and `/kaggle/working` paths only.

## Required order

1. Copy the validated GPU conversion packet artifacts into the Kaggle notebook input area.
2. Set deterministic seeds and cache directories.
3. Run a tiny smoke lane first.
4. Save checkpoint and receipt outputs every 25 steps or less.
5. Stop early before session timeout and preserve partial receipts.
6. Import outputs only through `KT_GPU_ARTIFACT_IMPORT_HASH_RECEIPT_CONTRACT`.

## Smoke phases

```text
environment_smoke
dataset_provenance_smoke
lora_smoke
qlora_optional_smoke_if_bitsandbytes_available
router_trace_smoke
artifact_import_hash_smoke
```

If `bitsandbytes` or GPU memory checks fail, exclude QLoRA from the first campaign with a receipt and fall back to LoRA. Do not convert that exclusion into a claim failure or a success claim.

## Required Kaggle outputs

```text
dataset_manifest.json
training_config.json
checkpoint_manifest.json
training_run_receipt.json
eval_receipt.json
router_trace.csv
candidate_provenance.json
negative_result_ledger.json
```

Every output must be hashable before import. Partial runs must still emit `training_run_receipt.json`, `checkpoint_manifest.json`, and `negative_result_ledger.json`.

## Target after this packet validates

```text
{TARGET_OUTCOME}
```
"""


def _execution_board(staging_passed: bool, blockers: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.gpu_conversion.execution_board.v1",
        "artifact_id": "KT_LOBE_ADAPTER_ROUTER_GPU_CONVERSION_EXECUTION_BOARD",
        "program_id": PROGRAM_ID,
        "generated_utc": utc_now_iso_z(),
        "current_posture": CURRENT_POSTURE,
        "target_outcome": TARGET_OUTCOME,
        "staging_passed": staging_passed,
        "next_lawful_move": "RUN_KT_GPU_CONVERSION_KAGGLE_SMOKE" if staging_passed else "PATCH_KT_GPU_CONVERSION_STAGING_PACKET",
        "blockers": list(blockers),
        "full_gpu_training_executed": False,
        **BLOCKED_CLAIMS,
    }


def _receipt(current_head: str, blockers: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    passed = not blockers
    return {
        "schema_id": "kt.gpu_conversion.staging_receipt.v1",
        "artifact_id": "KT_LOBE_ADAPTER_ROUTER_GPU_CONVERSION_STAGING_RECEIPT",
        "program_id": PROGRAM_ID,
        "generated_utc": utc_now_iso_z(),
        "current_head": current_head,
        "current_head_binding_semantics": "pre-staging live-input git head; generated GPU conversion artifacts are expected to be committed after this cutline",
        "current_posture": CURRENT_POSTURE,
        "selected_outcome": TARGET_OUTCOME if passed else "KT_GPU_CONVERSION_STAGING_BLOCKED__PATCH_REQUIRED",
        "staging_passed": passed,
        "training_execution_pending": passed,
        "full_gpu_training_executed": False,
        "trained_weights_exist_claimed": False,
        "next_lawful_move": "RUN_KT_GPU_CONVERSION_KAGGLE_SMOKE" if passed else "PATCH_KT_GPU_CONVERSION_STAGING_PACKET",
        "blockers": list(blockers),
        **BLOCKED_CLAIMS,
    }


def _claim_scan(root: Path, paths: Iterable[str]) -> Dict[str, Any]:
    violations: list[Dict[str, Any]] = []
    checked: list[str] = []
    for raw in paths:
        path = root / raw
        if not path.is_file():
            continue
        checked.append(raw)
        violations.extend(run_bounded_forward_streams.scan_claim_text(path.read_text(encoding="utf-8-sig"), source=raw))
    return {"checked_files": checked, "violation_count": len(violations), "violations": violations, "passed": not violations}


def run(*, output_root: Path | None = None) -> Dict[str, Any]:
    root = output_root or repo_root()
    current_head = _git_head(root)
    changed: list[str] = []

    cutline = _cutline(root, current_head)
    blockers: list[Dict[str, Any]] = [
        {"blocker_id": "missing_live_gpu_conversion_input", "path": item["path"], "role": item["role"]}
        for item in cutline["missing_live_inputs"]
    ]
    if not blockers:
        _assert_claim_boundary(root)

    json_outputs: Dict[str, Dict[str, Any]] = {
        OUTPUTS["cutline"]: cutline,
        OUTPUTS["classification"]: _classification(root),
        OUTPUTS["lobe_target_matrix"]: _lobe_targets(),
        OUTPUTS["adapter_target_matrix"]: _adapter_targets(),
        OUTPUTS["recipe_matrix"]: _recipe_matrix(),
        OUTPUTS["dataset_manifest"]: _dataset_manifest(),
        OUTPUTS["training_authorization"]: _training_authorization(),
        OUTPUTS["kaggle_packet"]: _kaggle_packet(),
        OUTPUTS["checkpoint_policy"]: _checkpoint_policy(),
        OUTPUTS["import_contract"]: _import_contract(),
        OUTPUTS["router_plan"]: _router_plan(),
        OUTPUTS["static_baseline"]: _static_baseline(),
        OUTPUTS["benchmark_gate"]: _benchmark_gate(),
        OUTPUTS["rollback_policy"]: _rollback_policy(),
        OUTPUTS["negative_schema"]: _negative_schema(),
        OUTPUTS["claim_receipt"]: _claim_receipt(current_head),
    }
    for raw, obj in json_outputs.items():
        if write_json_stable(root / raw, obj):
            changed.append(raw)

    if _write_text_stable(root / OUTPUTS["runbook"], _runbook()):
        changed.append(OUTPUTS["runbook"])

    claim_scan = _claim_scan(root, [OUTPUTS[key] for key in HUMAN_CLAIM_SCAN_OUTPUTS])
    if not claim_scan["passed"]:
        raise RuntimeError(f"FAIL_CLOSED: GPU conversion claim scan failed: {claim_scan['violations']}")

    staging_receipt = _receipt(current_head, blockers)
    execution_board = _execution_board(staging_receipt["staging_passed"], blockers)
    for raw, obj in {
        OUTPUTS["staging_receipt"]: staging_receipt,
        OUTPUTS["execution_board"]: execution_board,
    }.items():
        if write_json_stable(root / raw, obj):
            changed.append(raw)

    if blockers:
        raise RuntimeError(f"GPU conversion staging blocked: {blockers}")

    return {
        "target_outcome": TARGET_OUTCOME,
        "changed_outputs": changed,
        "claim_scan": claim_scan,
        "staging_receipt": staging_receipt,
        "execution_board": execution_board,
    }


def main(argv: Sequence[str] | None = None, *, output_root: Path | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run KT lobe/adapter/router GPU conversion staging.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    summary = run(output_root=output_root)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(TARGET_OUTCOME)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
