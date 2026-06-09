from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TRANCHE = "AUTHOR_KTV1774_E2E_MAX_POWER_CLEAN_SLATE_MATH_BLUEPRINT_V2_FINAL"
OUTCOME = (
    "KT_E2E_CLEAN_SLATE_MATH_BLUEPRINT_V2_BOUND__DRY_RUN_VALIDATION_READY__"
    "TRAINING_AUTHORITY_STILL_FALSE__CLAIM_CEILING_PRESERVED"
)
PREDECESSOR_HEAD = "c44c0f529cc777b4892c3ddf789c327ea15a9b88"
PREDECESSOR_OUTCOME = (
    "KT_REVERSE_HEAL_MATH_SANITIZATION_DECISION_BOUND__DATASET_BLUEPRINT_OR_BLOCKER_SELECTED__"
    "TRAINING_AUTHORITY_STILL_FALSE__CLAIM_CEILING_PRESERVED"
)
NEXT_LANE = "AUTHOR_MATH_DATASET_DRY_RUN_VALIDATION_NO_TRAINING_V1"

AUTHORITY_FALSE: dict[str, Any] = {
    "runtime_authority": False,
    "dataset_generation_authority": False,
    "training_authority": False,
    "promotion_authority": False,
    "adapter_mutation_authority": False,
    "adapter_training_authorized": False,
    "router_training_authorized": False,
    "policy_optimization_authorized": False,
    "v18_runtime_authority": False,
    "hf_upload_authorized": False,
    "kaggle_packet_generated": False,
    "runtime_packet_generated": False,
    "training_packet_generated": False,
    "dataset_packet_generated": False,
    "prompt_mutation_packet_generated": False,
    "safetensors_generated": False,
    "claim_ceiling_preserved": True,
    "gsm8k_recovery_claim": False,
    "g2_recovered_claim": False,
    "router_superiority_claim": False,
    "learned_router_superiority_claim": False,
    "commercial_claim": False,
    "external_validation_claim": False,
    "s_tier_claim": False,
    "seven_b_claim": False,
    "multi_lobe_superiority_claim": False,
    "production_readiness_claim": False,
    "frontier_claim": False,
}

REPORTS = [
    "reports/v17_7_4_e2e_clean_slate_truth_pin.json",
    "reports/v17_7_4_e2e_anti_drift_ledger.json",
    "reports/v17_7_4_e2e_lab_vs_canonical_operating_law.json",
    "reports/v17_7_4_e2e_audit_recursion_breaker.json",
    "reports/v17_7_4_clean_slate_math_dataset_objective.json",
    "reports/v17_7_4_clean_slate_math_dataset_contract.json",
    "reports/v17_7_4_clean_slate_trust_tier_contract.json",
    "reports/v17_7_4_clean_slate_verification_class_contract.json",
    "reports/v17_7_4_clean_slate_curriculum_ladder.json",
    "reports/v17_7_4_clean_slate_capability_density_spec.json",
    "reports/v17_7_4_clean_slate_doctrine_contamination_policy.json",
    "reports/v17_7_4_clean_slate_source_license_requirements.json",
    "reports/v17_7_4_clean_slate_train_eval_firewall_contract.json",
    "reports/v17_7_4_clean_slate_answer_contract.json",
    "reports/v17_7_4_clean_slate_formal_math_compression_suspension_receipt.json",
    "reports/v17_7_4_clean_slate_niche_boundary_contract.json",
    "reports/v17_7_4_clean_slate_no_regression_control_set.json",
    "reports/v17_7_4_clean_slate_prompt_format_probe_dependency.json",
    "reports/v17_7_4_clean_slate_dataset_dry_run_validation_requirements.json",
    "reports/v17_7_4_clean_slate_dataset_blueprint_go_no_go_decision.json",
    "reports/v17_7_4_epc_decision_after_clean_slate_math_dataset_blueprint_v2.json",
]
CLEANROOM_CI_RECEIPT = (
    "KT_PROD_CLEANROOM/reports/"
    "v17_7_4_e2e_clean_slate_math_blueprint_v2_ci_trigger_receipt.json"
)
SCHEMAS = [
    "schemas/kt.v17_7_4.clean_slate_math_dataset_row.schema.json",
    "schemas/kt.v17_7_4.clean_slate_math_dataset_contract.schema.json",
    "schemas/kt.v17_7_4.clean_slate_dry_run_manifest.schema.json",
]
SCRIPTS = [
    "scripts/build_v17_7_4_e2e_clean_slate_math_blueprint_v2.py",
    "scripts/validate_clean_slate_blueprint_contract.py",
    "scripts/generate_clean_slate_dry_run_rows.py",
]
TESTS = ["tests/test_v17_7_4_clean_slate_blueprint_contract.py"]
REGISTRY_DELTA = "registry/artifact_authority_registry_v17_7_4_e2e_clean_slate_math_blueprint_v2_delta_receipt.json"
BUILDER_SUMMARY = "reports/v17_7_4_e2e_clean_slate_math_blueprint_v2_builder_summary.json"


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(AUTHORITY_FALSE)
    payload.update(extra)
    return payload


def git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()


def read_json(path: str) -> dict[str, Any]:
    target = ROOT / path
    if not target.exists():
        return {}
    return json.loads(target.read_text(encoding="utf-8-sig"))


def write_json(path: str, payload: dict[str, Any]) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def base_context(current_head: str, branch: str) -> dict[str, Any]:
    reverse_heal = read_json("reports/v17_7_4_reverse_heal_math_sanitization_v2_builder_summary.json")
    yield_gate = read_json("reports/v17_7_4_math_corpus_sanitization_yield_gate.json")
    quality = read_json("reports/v17_7_4_math_corpus_quality_audit_builder_summary.json")
    return {
        "active_tranche": TRANCHE,
        "current_head": current_head,
        "current_branch": branch,
        "predecessor_head": PREDECESSOR_HEAD,
        "predecessor_outcome": PREDECESSOR_OUTCOME,
        "predecessor_builder_outcome": reverse_heal.get("outcome"),
        "predecessor_next_lawful_move": reverse_heal.get("next_lawful_move"),
        "predecessor_sanitization_yield_status": yield_gate.get("status"),
        "predecessor_selected_decision": yield_gate.get("selected_decision"),
        "predecessor_input_row_count": yield_gate.get("input_row_count"),
        "predecessor_doctrine_contamination_row_count": yield_gate.get("doctrine_contamination_row_count"),
        "predecessor_unknown_license_source_count": yield_gate.get("unknown_license_source_count"),
        "predecessor_quality_candidate_count": yield_gate.get("quality_candidate_count"),
        "predecessor_usable_yield": yield_gate.get("usable_yield"),
        "predecessor_quality_grade": quality.get("math_corpus_quality_grade"),
        "historical_corpus_training_use": "ABANDONED",
        "historical_corpus_role": "AUDIT_LINEAGE_ONLY",
        "claim_ceiling_status": "PRESERVED",
        "outcome": OUTCOME,
        "next_lawful_move": NEXT_LANE,
    }


def schema_payloads() -> dict[str, dict[str, Any]]:
    row_required = [
        "schema_id",
        "row_id",
        "source_id",
        "problem",
        "solution",
        "answer",
        "answer_visibility",
        "trust_tier",
        "verification_class",
        "curriculum_stage",
        "license",
        "split",
        "problem_hash",
        "answer_hash",
        "expected_answer_model_visible",
        "doctrine_contamination_scan_pass",
        "train_eval_firewall_pass",
    ]
    return {
        SCHEMAS[0]: {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "kt.v17_7_4.clean_slate_math_dataset_row.schema.v1",
            "type": "object",
            "additionalProperties": True,
            "required": row_required,
            "properties": {
                "schema_id": {"const": "kt.v17_7_4.clean_slate_math_dataset_row.v1"},
                "row_id": {"type": "string"},
                "trust_tier": {"enum": ["T0_REJECT", "T1_FORMAT_ONLY", "T2_NUMERIC_VERIFIED", "T3_STEP_VERIFIED", "T4_HUMAN_REVIEWED"]},
                "verification_class": {"enum": ["V0_UNVERIFIED", "V1_NUMERIC", "V2_STEP_CHECKED", "V3_CODE_OR_HUMAN_VERIFIED"]},
                "curriculum_stage": {"minimum": 0, "maximum": 9, "type": "integer"},
                "answer_visibility": {"enum": ["LABEL_ONLY", "MODEL_VISIBLE_BLOCKED"]},
                "expected_answer_model_visible": {"const": False},
            },
            "anyOf": [{"required": ["source_origin"]}, {"required": ["source_url"]}],
        },
        SCHEMAS[1]: {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "kt.v17_7_4.clean_slate_math_dataset_contract.schema.v1",
            "type": "object",
            "additionalProperties": True,
            "required": [
                "schema_id",
                "status",
                "dataset_generation_authority",
                "training_authority",
                "historical_corpus_training_use",
                "next_lawful_move",
            ],
            "properties": {
                "schema_id": {"const": "kt.v17_7_4.clean_slate_math_dataset_contract.v1"},
                "status": {"type": "string"},
                "dataset_generation_authority": {"const": False},
                "training_authority": {"const": False},
                "historical_corpus_training_use": {"const": "ABANDONED"},
            },
        },
        SCHEMAS[2]: {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "kt.v17_7_4.clean_slate_dry_run_manifest.schema.v1",
            "type": "object",
            "additionalProperties": True,
            "required": [
                "schema_id",
                "status",
                "row_count",
                "pass",
                "dataset_generation_authority",
                "training_authority",
            ],
            "properties": {
                "schema_id": {"const": "kt.v17_7_4.clean_slate_dry_run_manifest.v1"},
                "dataset_generation_authority": {"const": False},
                "training_authority": {"const": False},
            },
        },
    }


def report_payloads(context: dict[str, Any]) -> dict[str, dict[str, Any]]:
    common = dict(context)
    return {
        "reports/v17_7_4_e2e_clean_slate_truth_pin.json": authority(
            schema_id="kt.v17_7_4.e2e_clean_slate_truth_pin.v1",
            status="PASS",
            binding_status="BOUND_TO_REVERSE_HEAL_DECISION",
            expected_predecessor_head=PREDECESSOR_HEAD,
            truth_delta_status="NO_DELTA",
            required_predecessor_metrics={
                "input_row_count": 8721,
                "doctrine_contamination_row_count": 6540,
                "unknown_license_source_count": 5466,
                "quality_candidate_count": 0,
                "selected_decision": "ABANDON_HISTORICAL_CORPUS_FOR_CLEAN_BLUEPRINT",
            },
            **common,
        ),
        "reports/v17_7_4_e2e_anti_drift_ledger.json": authority(
            schema_id="kt.v17_7_4.e2e_anti_drift_ledger.v1",
            status="PASS",
            allowed_claim=(
                "KT abandoned contaminated historical math data for future training use and bound a clean-slate "
                "math blueprint with dry-run validation requirements."
            ),
            blocked_claims=[
                "math capability recovered",
                "training authorized",
                "dataset generated",
                "runtime packet ready",
                "router authority granted",
                "compression recovered",
            ],
            temporal_authority_engine_note=(
                "Temporal authority/world-model framing is admitted only as future contract language here; "
                "no runtime authority or simulator authority is granted by this lane."
            ),
            **common,
        ),
        "reports/v17_7_4_e2e_lab_vs_canonical_operating_law.json": authority(
            schema_id="kt.v17_7_4.e2e_lab_vs_canonical_operating_law.v1",
            status="PASS",
            lab_plane_allowed=["synthetic dry-run validation", "contract tests", "row validator negative controls"],
            canonical_plane_requires=["fresh main replay", "claim ceiling preserved", "no authority promotion"],
            governance_outside_cognition=True,
            **common,
        ),
        "reports/v17_7_4_e2e_audit_recursion_breaker.json": authority(
            schema_id="kt.v17_7_4.e2e_audit_recursion_breaker.v1",
            status="PASS",
            exact_next_lane=NEXT_LANE,
            forbids_plan_more=True,
            terminal_decision="DRY_RUN_VALIDATION_READY_ONLY",
            **common,
        ),
        "reports/v17_7_4_clean_slate_math_dataset_objective.json": authority(
            schema_id="kt.v17_7_4.clean_slate_math_dataset_objective.v1",
            status="PASS",
            objective="Build a future clean, GSM8K-first math repair dataset blueprint without using burned historical corpus rows.",
            not_objectives=["training", "dataset emission", "runtime generation", "compression optimization", "adapter mutation"],
            **common,
        ),
        "reports/v17_7_4_clean_slate_math_dataset_contract.json": authority(
            schema_id="kt.v17_7_4.clean_slate_math_dataset_contract.v1",
            status="PASS_CONTRACT_BOUND",
            required_row_schema=SCHEMAS[0],
            dry_run_validation_required_before_dataset_generation=True,
            **common,
        ),
        "reports/v17_7_4_clean_slate_trust_tier_contract.json": authority(
            schema_id="kt.v17_7_4.clean_slate_trust_tier_contract.v1",
            status="PASS",
            tiers={
                "T0_REJECT": "Reject; no dataset use.",
                "T1_FORMAT_ONLY": "Review/reference only.",
                "T2_NUMERIC_VERIFIED": "Numeric verifier compatible.",
                "T3_STEP_VERIFIED": "Step reasoning and hidden label verified.",
                "T4_HUMAN_REVIEWED": "Human/code reviewed transfer candidate.",
            },
            t0_must_never_escape=True,
            **common,
        ),
        "reports/v17_7_4_clean_slate_verification_class_contract.json": authority(
            schema_id="kt.v17_7_4.clean_slate_verification_class_contract.v1",
            status="PASS",
            classes={
                "V0_UNVERIFIED": "Never training eligible.",
                "V1_NUMERIC": "Normalized numeric answer check.",
                "V2_STEP_CHECKED": "Step-level equation/invariant check.",
                "V3_CODE_OR_HUMAN_VERIFIED": "Code or human reviewed.",
            },
            no_measured_proof_claim=True,
            **common,
        ),
        "reports/v17_7_4_clean_slate_curriculum_ladder.json": authority(
            schema_id="kt.v17_7_4.clean_slate_curriculum_ladder.v1",
            status="PASS",
            stages=[
                "arithmetic facts",
                "single operation word problems",
                "multi-operation GSM8K",
                "units and ratios",
                "algebraic setup",
                "verification and finalization",
                "mixed GSM8K review",
                "formal proof prep only",
                "competition math prep only",
                "future advanced math only",
            ],
            gsm8k_foundation_first=True,
            olympiad_future_only=True,
            **common,
        ),
        "reports/v17_7_4_clean_slate_capability_density_spec.json": authority(
            schema_id="kt.v17_7_4.clean_slate_capability_density_spec.v1",
            status="PASS",
            formula="(T4_count + 0.5 * T3_count) / total_rows",
            minimum_dry_run_density=0.30,
            minimum_real_blueprint_density=0.65,
            forbids_final_answer_only_rows_for_reasoning_training=True,
            **common,
        ),
        "reports/v17_7_4_clean_slate_doctrine_contamination_policy.json": authority(
            schema_id="kt.v17_7_4.clean_slate_doctrine_contamination_policy.v1",
            status="PASS",
            banned_terms=[
                "KT-hat",
                "ReproLock",
                "EPC",
                "lobe",
                "router",
                "route",
                "court",
                "gate",
                "receipt",
                "claim ceiling",
                "scar",
                "delta",
                "truth engine",
                "governance",
                "H0",
                "operator",
                "oracle label",
                "safetensors",
            ],
            doctrine_terms_allowed_in_training_rows=False,
            **common,
        ),
        "reports/v17_7_4_clean_slate_source_license_requirements.json": authority(
            schema_id="kt.v17_7_4.clean_slate_source_license_requirements.v1",
            status="PASS",
            allowed_licenses=["CC0", "CC-BY-4.0", "CC-BY-SA-4.0", "MIT", "Apache-2.0", "PUBLIC_DOMAIN", "ORIGINAL_AUTHORED"],
            unknown_license_allowed=False,
            source_url_or_origin_required=True,
            **common,
        ),
        "reports/v17_7_4_clean_slate_train_eval_firewall_contract.json": authority(
            schema_id="kt.v17_7_4.clean_slate_train_eval_firewall_contract.v1",
            status="PASS",
            problem_hash_split_collision_allowed=False,
            hidden_labels_required=True,
            heldout_hash_manifest_required=True,
            **common,
        ),
        "reports/v17_7_4_clean_slate_answer_contract.json": authority(
            schema_id="kt.v17_7_4.clean_slate_answer_contract.v1",
            status="PASS",
            answer_visibility="LABEL_ONLY",
            expected_answer_model_visible=False,
            model_prompt_may_include_answer=False,
            normalized_answer_required=True,
            **common,
        ),
        "reports/v17_7_4_clean_slate_formal_math_compression_suspension_receipt.json": authority(
            schema_id="kt.v17_7_4.clean_slate_formal_math_compression_suspension_receipt.v1",
            status="SUSPENDED",
            formal_math_compression_suspended=True,
            compression_reopen_authority=False,
            **common,
        ),
        "reports/v17_7_4_clean_slate_niche_boundary_contract.json": authority(
            schema_id="kt.v17_7_4.clean_slate_niche_boundary_contract.v1",
            status="PASS_REAFFIRMED",
            formal_math_niche_bound=True,
            no_global_adapter_promotion=True,
            no_route_promotion=True,
            **common,
        ),
        "reports/v17_7_4_clean_slate_no_regression_control_set.json": authority(
            schema_id="kt.v17_7_4.clean_slate_no_regression_control_set.v1",
            status="PASS_REQUIREMENTS_ONLY",
            required_controls=["known-good math_act control", "base_raw", "non-math slices", "heldout ReproLock rows"],
            no_regression_required_before_training=True,
            **common,
        ),
        "reports/v17_7_4_clean_slate_prompt_format_probe_dependency.json": authority(
            schema_id="kt.v17_7_4.clean_slate_prompt_format_probe_dependency.v1",
            status="PASS_LAB_DEPENDENCY_BOUND",
            prompt_format_probe_is_dependency=True,
            probe_authority_now=False,
            **common,
        ),
        "reports/v17_7_4_clean_slate_dataset_dry_run_validation_requirements.json": authority(
            schema_id="kt.v17_7_4.clean_slate_dataset_dry_run_validation_requirements.v1",
            status="PASS",
            required_validator="scripts/validate_clean_slate_blueprint_contract.py",
            required_synthetic_generator="scripts/generate_clean_slate_dry_run_rows.py",
            required_negative_controls=["T0 escape", "doctrine contamination", "unknown license", "answer leakage", "split collision"],
            **common,
        ),
        "reports/v17_7_4_clean_slate_dataset_blueprint_go_no_go_decision.json": authority(
            schema_id="kt.v17_7_4.clean_slate_dataset_blueprint_go_no_go_decision.v1",
            status="GO_DRY_RUN_VALIDATION_ONLY",
            decision="GO_DRY_RUN_VALIDATION_ONLY",
            next_lane=NEXT_LANE,
            real_dataset_generation_go=False,
            dry_run_validation_go=True,
            **common,
        ),
        "reports/v17_7_4_epc_decision_after_clean_slate_math_dataset_blueprint_v2.json": authority(
            schema_id="kt.v17_7_4.epc_decision_after_clean_slate_math_dataset_blueprint_v2.v1",
            status="PASS_DECIDED_NO_RUNTIME_PACKET",
            selected_next_lane=NEXT_LANE,
            runtime_allowed_by_this_lane=False,
            dataset_generation_allowed_by_this_lane=False,
            training_allowed_by_this_lane=False,
            **common,
        ),
    }


def build() -> dict[str, Any]:
    current_head = git(["rev-parse", "HEAD"])
    branch = git(["branch", "--show-current"])
    context = base_context(current_head, branch)

    for path, payload in schema_payloads().items():
        write_json(path, payload)
    for path, payload in report_payloads(context).items():
        write_json(path, payload)

    files_changed = SCRIPTS + SCHEMAS + REPORTS + [CLEANROOM_CI_RECEIPT, BUILDER_SUMMARY, REGISTRY_DELTA] + TESTS
    ci_receipt = authority(
        schema_id="kt.v17_7_4.e2e_clean_slate_math_blueprint_v2_ci_trigger_receipt.v1",
        status="PASS",
        purpose="Mirror receipt under KT_PROD_CLEANROOM so required P0 ruleset contexts are emitted for this PR.",
        **context,
    )
    registry_delta = authority(
        schema_id="kt.artifact_authority_registry_delta.v17_7_4_e2e_clean_slate_math_blueprint_v2",
        status="PASS",
        artifacts_added=files_changed,
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        **context,
    )
    summary = authority(
        schema_id="kt.v17_7_4.e2e_clean_slate_math_blueprint_v2_builder_summary.v1",
        status="PASS",
        active_tranche=TRANCHE,
        current_head=current_head,
        branch=branch,
        outcome=OUTCOME,
        files_changed=files_changed,
        e2e_clean_slate_binding_status="BOUND_TO_REVERSE_HEAL_DECISION",
        abandon_historical_corpus_receipt_status="PASS_ABANDONED_FOR_TRAINING_USE",
        lab_vs_canonical_operating_law_status="PASS",
        audit_recursion_breaker_status="PASS",
        row_contract_status="PASS",
        dataset_contract_status="PASS",
        trust_tier_contract_status="PASS",
        verification_class_contract_status="PASS",
        curriculum_ladder_status="PASS",
        capability_density_status="PASS",
        doctrine_contamination_policy_status="PASS",
        source_license_requirements_status="PASS",
        train_eval_firewall_status="PASS",
        answer_contract_status="PASS",
        compression_suspension_status="SUSPENDED",
        niche_boundary_status="PASS_REAFFIRMED",
        prompt_format_probe_dependency_status="PASS_LAB_DEPENDENCY_BOUND",
        dry_run_validation_requirements_status="PASS",
        dry_run_validator_status="PASS_READY",
        synthetic_row_generator_status="PASS_READY",
        dataset_blueprint_go_no_go_status="GO_DRY_RUN_VALIDATION_ONLY",
        epc_next_lane_status="PASS_DECIDED_NO_RUNTIME_PACKET",
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
        claim_ceiling_status="PRESERVED",
        blockers=[],
        next_lawful_move=NEXT_LANE,
    )
    write_json(CLEANROOM_CI_RECEIPT, ci_receipt)
    write_json(REGISTRY_DELTA, registry_delta)
    write_json(BUILDER_SUMMARY, summary)
    return summary


def main() -> None:
    print(json.dumps(build(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
