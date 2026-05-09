from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable


AUTHORITY_BRANCH = "prep/kt-e2e-closure-adaptive-ratification-order-v1"
REPLAY_BRANCH_PREFIX = "replay/kt-e2e-closure-adaptive-ratification-order"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

CAMPAIGN_ID = "KT_E2E_CLOSURE_ADAPTIVE_RATIFICATION_AND_7B_AMPLIFICATION_BENCHMARK_ORDER_v1"
AUTHORITY = "PREP_ONLY"
PREVIOUS_OUTCOME = "B04_R6_CANARY_EVIDENCE_REVIEW_VALIDATED__EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT"
PREVIOUS_NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_EXPANDED_CANARY_AUTHORIZATION_PACKET"
SELECTED_OUTCOME = (
    "KT_E2E_CLOSURE_ADAPTIVE_RATIFICATION_AND_7B_AMPLIFICATION_BENCHMARK_ORDER_BOUND__"
    "CAMPAIGN_VALIDATION_NEXT"
)
NEXT_LAWFUL_MOVE = "VALIDATE_KT_E2E_CLOSURE_ADAPTIVE_RATIFICATION_AND_7B_AMPLIFICATION_BENCHMARK_ORDER"

VALIDATION_RECEIPT = "b04_r6_canary_evidence_review_validation_receipt.json"
CANARY_DECISION_RECEIPT = "b04_r6_canary_post_run_decision_matrix_validation_receipt.json"

OUTPUTS = {
    "campaign_order": "kt_e2e_closure_campaign_order_v1.json",
    "campaign_order_receipt": "kt_e2e_closure_campaign_order_v1_receipt.json",
    "campaign_board": "kt_e2e_closure_campaign_board.json",
    "claim_ceiling": "kt_claim_ceiling_current_state.json",
    "boundary_reratification_plan": "kt_canonical_lab_archive_commercial_boundary_reratification_plan.json",
    "proof_factory_contract": "kt_proof_factory_v1_prep_contract.json",
    "claim_compiler_contract": "kt_claim_compiler_v1_prep_contract.json",
    "promotion_engine_contract": "kt_promotion_engine_v1_prep_contract.json",
    "lobe_ratification_factory": "kt_lobe_ratification_factory_prep_contract.json",
    "adapter_tournament_factory": "kt_adapter_tournament_factory_prep_contract.json",
    "benchmark_constitution": "kt_benchmark_constitution_prep_contract.json",
    "amplification_ablation_plan": "kt_7b_amplification_ablation_plan.json",
    "external_verifier_contract": "kt_external_verifier_prep_contract.json",
    "reaudit_readiness_contract": "kt_reaudit_readiness_prep_contract.json",
    "commercial_truth_plane": "kt_commercial_truth_plane_prep_contract.json",
    "gpu_training_gate": "kt_gpu_training_readiness_gate.json",
    "competition_factory": "kt_competition_factory_prep_contract.json",
    "next_lawful_move": "kt_next_lawful_move_receipt.json",
}

REQUIRED_CORRIDORS = (
    "R6_CORRIDOR",
    "POST_CANARY_DECISION",
    "EXPANDED_CANARY_AND_CUTOVER_PATH",
    "PROOF_FACTORY",
    "CLAIM_COMPILER",
    "PROMOTION_ENGINE",
    "LOBE_FACTORY",
    "ADAPTER_TOURNAMENT_FACTORY",
    "BENCHMARK_CONSTITUTION",
    "EXTERNAL_VERIFIER",
    "COMMERCIAL_TRUTH_PLANE",
    "REAUDIT_READINESS",
    "PACKAGE_PROMOTION_BLOCKERS",
    "GPU_TRAINING_READINESS",
    "COMPETITION_FACTORY",
)

ABLATION_LADDER = (
    "A0_RAW_7B_BASELINE",
    "A1_7B_PLUS_PROMPT_DISCIPLINE",
    "A2_7B_PLUS_RETRIEVAL",
    "A3_7B_PLUS_TOOLS",
    "A4_7B_PLUS_VERIFIER_LOOP",
    "A5_7B_PLUS_ADAPTERS",
    "A6_7B_PLUS_ROUTER_TRIAGE",
    "A7_7B_PLUS_LOBES",
    "A8_7B_PLUS_FULL_KT_GOVERNANCE_RECEIPTS_REPLAY",
)

RATIFICATION_ORDER = (
    "canonical_lab_archive_commercial_boundary",
    "truth_engine_and_execution_board_authority",
    "crucible_registry",
    "policy_c_pressure_taxonomy",
    "epoch_coverage_matrix",
    "adapter_lifecycle_and_lineage",
    "tournament_protocol",
    "promotion_merge_rollback_law",
    "router_and_lobe_ratification",
    "benchmark_constitution",
    "external_verifier_and_reaudit",
    "commercial_truth_plane",
)

LOBE_RATIFICATION_ORDER = (
    "lobe_role_registry",
    "lobe_abi_io_contract",
    "lobe_source_packet",
    "lobe_candidate_generation",
    "lobe_admissibility",
    "lobe_shadow_eval",
    "lobe_promotion_review",
    "lobe_rollback_retirement_law",
)

LOBE_FAMILIES = (
    "proof_validator",
    "auditor",
    "contradiction_checker",
    "math_reasoner",
    "code_operator",
    "memory_retrieval",
    "commercial_boundary",
    "external_verifier",
    "tournament_judge",
    "adapter_evaluator",
    "strategy_planner",
)

HARD_PROHIBITIONS = (
    "runtime_cutover",
    "r6_opening",
    "package_promotion",
    "commercial_activation_claims",
    "lobe_activation",
    "adapter_promotion",
    "gpu_training_as_authority",
    "seven_b_amplification_claims",
    "truth_engine_law_mutation",
    "trust_zone_law_mutation",
)


def _prep_guard() -> Dict[str, Any]:
    return {
        "authority": AUTHORITY,
        "runtime_cutover_authorized": False,
        "r6_open": False,
        "lobe_activation_authorized": False,
        "adapter_promotion_authorized": False,
        "package_promotion_authorized": False,
        "commercial_activation_claim_authorized": False,
        "gpu_training_authorized": False,
        "seven_b_amplification_proven": False,
        "truth_engine_law_mutated": False,
        "trust_zone_law_mutated": False,
        "cannot_authorize_runtime_cutover": True,
        "cannot_open_r6": True,
        "cannot_authorize_lobe_escalation": True,
        "cannot_authorize_package_promotion": True,
        "cannot_authorize_commercial_activation_claims": True,
        "cannot_mutate_truth_engine_law": True,
        "cannot_mutate_trust_zone_law": True,
    }


def _ensure_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch not in ALLOWED_BRANCHES and not branch.startswith(REPLAY_BRANCH_PREFIX):
        allowed = ", ".join(sorted([*ALLOWED_BRANCHES, f"{REPLAY_BRANCH_PREFIX}*"]))
        raise RuntimeError(f"FAIL_CLOSED: must run on one of: {allowed}; got: {branch}")
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before campaign order generation")
    return branch


def _load_prior_validation(reports_root: Path) -> Dict[str, Any]:
    payload = load_json(reports_root / VALIDATION_RECEIPT)
    if str(payload.get("selected_outcome", "")).strip() != PREVIOUS_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: campaign order requires canonical canary evidence validation outcome")
    if str(payload.get("next_lawful_move", "")).strip() != PREVIOUS_NEXT_LAWFUL_MOVE:
        raise RuntimeError("FAIL_CLOSED: campaign order requires expanded canary authorization as prior next move")
    if bool(payload.get("runtime_cutover_authorized", False)) or bool(payload.get("r6_open", False)):
        raise RuntimeError("FAIL_CLOSED: prior validation cannot authorize cutover or R6 opening")
    return payload


def _base(*, artifact_id: str, branch: str, head: str, current_main_head: str, generated_utc: str) -> Dict[str, Any]:
    return {
        **_prep_guard(),
        "schema_id": "kt.e2e_closure.adaptive_ratification_order.v1",
        "artifact_id": artifact_id,
        "campaign_id": CAMPAIGN_ID,
        "created_utc": generated_utc,
        "current_branch": branch,
        "head": head,
        "current_main_head": current_main_head,
        "predecessor_outcome": PREVIOUS_OUTCOME,
        "previous_next_lawful_move": PREVIOUS_NEXT_LAWFUL_MOVE,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "hard_prohibitions": list(HARD_PROHIBITIONS),
        "claim_ceiling": "CANARY_EVIDENCE_VALIDATED__CAMPAIGN_CONSTITUTION_PREP_ONLY",
    }


def _corridor(
    corridor: str,
    *,
    status: str,
    authoritative_next: str,
    prep_only_tracks: Sequence[str],
    blockers: Sequence[str],
    receipts: Sequence[str],
) -> Dict[str, Any]:
    return {
        "corridor": corridor,
        "status": status,
        "authoritative_next": authoritative_next,
        "blocked_authorities": [
            "RUNTIME_CUTOVER",
            "R6_OPEN",
            "PACKAGE_PROMOTION",
            "COMMERCIAL_ACTIVATION_CLAIMS",
            "LOBE_ACTIVATION",
            "ADAPTER_PROMOTION",
        ],
        "claim_ceiling": "CANARY_EVIDENCE_VALIDATED_ONLY",
        "prep_only_tracks": list(prep_only_tracks),
        "blockers": list(blockers),
        "receipts": list(receipts),
    }


def _payloads(*, reports_root: Path, branch: str, head: str, current_main_head: str) -> Dict[str, Dict[str, Any]]:
    generated_utc = utc_now_iso_z()
    validation_receipt = _load_prior_validation(reports_root)
    validation_receipt_path = reports_root / VALIDATION_RECEIPT
    decision_receipt_path = reports_root / CANARY_DECISION_RECEIPT
    prior_bindings = {
        "canary_evidence_validation_receipt": validation_receipt_path.as_posix(),
        "canary_evidence_validation_receipt_hash": file_sha256(validation_receipt_path),
        "canary_post_run_decision_matrix_validation_receipt": decision_receipt_path.as_posix(),
        "canary_post_run_decision_matrix_validation_receipt_hash": file_sha256(decision_receipt_path),
    }

    common_base = {
        "campaign_purpose": "Govern the next KT E2E closure campaign before launching broad adaptive work.",
        "required_statement": (
            "KT does not claim small models are secretly giant models. KT tests where governed substrate makes "
            "smaller models act above class, and proves where it does not."
        ),
        "ratification_order": list(RATIFICATION_ORDER),
        "prior_bindings": prior_bindings,
    }

    payloads: Dict[str, Dict[str, Any]] = {}
    for role, filename in OUTPUTS.items():
        artifact_id = filename.removesuffix(".json").upper()
        payloads[role] = {
            **_base(
                artifact_id=artifact_id,
                branch=branch,
                head=head,
                current_main_head=current_main_head,
                generated_utc=generated_utc,
            ),
            **common_base,
            "output_role": role,
        }

    payloads["campaign_order"].update(
        {
            "campaign_sections": [
                "current_canonical_state_and_pr102_boundary",
                "protected_merge_and_replay_on_main_closure",
                "canonical_lab_archive_commercial_boundary_enforcement",
                "truth_engine_and_execution_board_authority",
                "crucible_epoch_policy_c_ratification",
                "adapter_lifecycle_and_lawful_training",
                "tournament_promotion_merge_rollback_law",
                "router_and_lobe_ratification",
                "capability_atlas",
                "seven_b_amplification_benchmark",
                "external_comparative_benchmark",
                "external_replay_and_hostile_audit_ladder",
                "commercial_proof_surface",
                "final_success_fail_criteria",
            ],
            "current_canonical_state": {
                "main": current_main_head,
                "outcome": PREVIOUS_OUTCOME,
                "next_lawful_move_from_prior_lane": PREVIOUS_NEXT_LAWFUL_MOVE,
                "campaign_order_authority": AUTHORITY,
            },
            "campaign_success_criteria": [
                "single campaign board controls broad motion",
                "single claim ceiling prevents excitement drift",
                "benchmark constitution precedes 7B amplification claims",
                "lobe and adapter factories precede GPU-backed training authority",
                "external verifier and reaudit paths precede package or commercial promotion",
            ],
        }
    )

    payloads["campaign_board"].update(
        {
            "corridors": [
                _corridor(
                    "R6_CORRIDOR",
                    status="CANARY_EVIDENCE_VALIDATED__EXPANDED_CANARY_AUTHORIZATION_AUTHORSHIP_NEXT",
                    authoritative_next=PREVIOUS_NEXT_LAWFUL_MOVE,
                    prep_only_tracks=["campaign_constitution", "claim_ceiling", "proof_factory"],
                    blockers=["expanded_canary_authorization_packet_not_authored"],
                    receipts=[VALIDATION_RECEIPT],
                ),
                _corridor(
                    "POST_CANARY_DECISION",
                    status="DECISION_MATRIX_VALIDATED",
                    authoritative_next=PREVIOUS_NEXT_LAWFUL_MOVE,
                    prep_only_tracks=["expanded_canary_authorization_scaffold"],
                    blockers=["expanded_canary_not_authorized_or_executed"],
                    receipts=[CANARY_DECISION_RECEIPT],
                ),
                *[
                    _corridor(
                        corridor,
                        status="PREP_ONLY_CONSTITUTION_REQUIRED",
                        authoritative_next=NEXT_LAWFUL_MOVE,
                        prep_only_tracks=[corridor.lower()],
                        blockers=["campaign_order_validation_required"],
                        receipts=[],
                    )
                    for corridor in REQUIRED_CORRIDORS
                    if corridor not in {"R6_CORRIDOR", "POST_CANARY_DECISION"}
                ],
            ]
        }
    )

    payloads["claim_ceiling"].update(
        {
            "allowed_claims": [
                "AFSH passed limited-runtime canary under bounded packet law.",
                "The canary evidence review is validated on canonical main.",
                "Expanded canary authorization packet authorship is the next R6 lawful move.",
                "Runtime cutover remains blocked.",
                "R6 remains closed.",
                "Package promotion remains blocked.",
                "Commercial activation claims remain blocked.",
            ],
            "forbidden_claims": [
                "KT is production activated.",
                "R6 is open.",
                "AFSH is commercially live.",
                "Package promotion is complete.",
                "7B amplification is proven.",
                "Lobes are ratified.",
                "KT beats larger models generally.",
            ],
        }
    )

    payloads["boundary_reratification_plan"].update(
        {
            "zones": ["CANONICAL", "LAB", "ARCHIVE", "COMMERCIAL"],
            "required_plan": [
                "canonical_scope_manifest_refresh",
                "trust_zone_registry_refresh",
                "execution_board_authority_check",
                "truth_engine_contract_check",
                "posture_contract_check",
                "live_validation_index_refresh",
                "posture_conflict_receipt",
            ],
        }
    )

    payloads["proof_factory_contract"].update(
        {
            "factory_outputs": [
                "lane_spec_schema",
                "operator_template",
                "validator_template",
                "replay_template",
                "reason_code_template",
                "base_invariant_suite",
                "paired_lane_bundle",
            ],
            "factory_status": "PREP_ONLY_NOT_AUTHORITY",
        }
    )

    payloads["claim_compiler_contract"].update(
        {
            "derivation_rule": "claims_derive_from_receipts_not_prose",
            "required_inputs": ["claim_ceiling", "current_state_receipts", "forbidden_claims_registry"],
            "required_outputs": ["allowed_claims", "forbidden_claims", "claim_drift_receipt"],
        }
    )

    payloads["promotion_engine_contract"].update(
        {
            "promotion_law": ["source_packet", "candidate_generation", "admissibility", "eval", "promotion_review", "rollback"],
            "applies_to": ["package", "adapter", "lobe", "router", "commercial_claim"],
        }
    )

    payloads["lobe_ratification_factory"].update(
        {
            "lobe_ratification_order": list(LOBE_RATIFICATION_ORDER),
            "candidate_lobe_families": list(LOBE_FAMILIES),
            "lobe_activation": "BLOCKED_UNTIL_FUTURE_AUTHORITY",
        }
    )

    payloads["adapter_tournament_factory"].update(
        {
            "factory_order": [
                "crucible_registry",
                "policy_c_pressure_taxonomy",
                "epoch_coverage_matrix",
                "adapter_registry",
                "adapter_lineage_manifest",
                "adapter_eval_receipt_schema",
                "tournament_protocol",
                "merge_law",
                "anti_gaming_controls",
            ],
            "adapter_promotion": "BLOCKED_UNTIL_FUTURE_AUTHORITY",
        }
    )

    payloads["benchmark_constitution"].update(
        {
            "benchmark_question": (
                "Which KT layers add measurable lift, where, at what cost, with what proof burden, and under "
                "what failure conditions?"
            ),
            "comparison_targets": [
                "raw_7b",
                "larger_open_models",
                "static_adapter_baseline",
                "monolith_only_baseline",
                "router_baseline",
                "tool_only_baseline",
                "human_audited_proof_baseline",
            ],
            "negative_result_policy": "negative_results_are_required_evidence_not_failure_theater",
        }
    )

    payloads["amplification_ablation_plan"].update(
        {
            "ablation_ladder": list(ABLATION_LADDER),
            "theorem_status": "NOT_PROVEN",
            "theorem_to_test": (
                "Governed substrate, routing, retrieval, tools, verifier loops, adapters, lobes, and evidence "
                "discipline may make a smaller model perform above raw class on bounded task families."
            ),
        }
    )

    payloads["external_verifier_contract"].update(
        {
            "externality_ladder": [
                "same_host_replay",
                "cross_host_replay",
                "independent_hostile_replay",
                "public_challenge",
                "external_comparative_report",
            ],
            "public_claims_require_external_verification": True,
        }
    )

    payloads["reaudit_readiness_contract"].update(
        {
            "reaudit_requirements": [
                "benchmark_constitution_validated",
                "negative_result_ledger_present",
                "external_replay_bundle_present",
                "claim_compiler_active",
                "commercial_boundary_current",
            ]
        }
    )

    payloads["commercial_truth_plane"].update(
        {
            "commercial_surface_status": "PREP_ONLY",
            "required_before_commercial_claims": [
                "claim_compiler_validated",
                "external_verifier_path_validated",
                "operator_runbook_current",
                "deployment_profile_current",
                "data_governance_pack_current",
                "package_promotion_review_validated",
            ],
        }
    )

    payloads["gpu_training_gate"].update(
        {
            "gpu_training_readiness": "BLOCKED_PENDING_TRAINING_LAW",
            "required_before_gpu_training": [
                "source_packet",
                "training_authorization",
                "candidate_generation",
                "admissibility",
                "eval",
                "promotion",
                "benchmark",
                "rollback",
            ],
        }
    )

    payloads["competition_factory"].update(
        {
            "competition_factory_status": "PREP_ONLY",
            "candidate_competitions": ["kaggle_style", "aimo_style", "arc_style", "proof_replay_challenge"],
            "submission_requires": [
                "competition_source_packet",
                "training_authorization_if_needed",
                "submission_packet",
                "claim_boundary",
                "post_submission_evidence_review",
            ],
        }
    )

    payloads["next_lawful_move"].update(
        {
            "receipt_type": "NEXT_LAWFUL_MOVE",
            "next_lawful_move": NEXT_LAWFUL_MOVE,
            "after_validation_parallel_tracks": [
                "proof_factory_v1",
                "claim_compiler_v1",
                "promotion_engine_v1",
                "lobe_ratification_factory",
                "adapter_tournament_factory",
                "benchmark_constitution",
                "external_verifier_packet",
                "commercial_truth_plane",
                "gpu_training_readiness",
                "competition_factory",
            ],
        }
    )

    output_hashes = {}
    for role, filename in OUTPUTS.items():
        if role == "campaign_order_receipt":
            continue
        output_hashes[f"{role}_planned_path"] = f"KT_PROD_CLEANROOM/reports/{filename}"

    payloads["campaign_order_receipt"].update(
        {
            "receipt_type": "CAMPAIGN_ORDER_AUTHORING_RECEIPT",
            "campaign_order_bound": True,
            "expected_outcome": SELECTED_OUTCOME,
            "validation_next": NEXT_LAWFUL_MOVE,
            "planned_outputs": output_hashes,
        }
    )

    return payloads


def run(*, reports_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    reports_root = reports_root or root / "KT_PROD_CLEANROOM" / "reports"
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    branch = _ensure_context(root)
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")

    payloads = _payloads(reports_root=reports_root, branch=branch, head=head, current_main_head=current_main_head)
    for role, filename in OUTPUTS.items():
        write_json_stable(reports_root / filename, payloads[role])
    return payloads["campaign_order"]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Author the prep-only KT E2E adaptive ratification campaign order.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    reports_root = (repo_root() / args.reports_root).resolve()
    result = run(reports_root=reports_root)
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
