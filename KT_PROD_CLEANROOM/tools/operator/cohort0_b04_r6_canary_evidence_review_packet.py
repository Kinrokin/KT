from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_limited_runtime_canary as canary
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-canary-evidence-e2e-superlane"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
SUPERLANE_ID = "KT_E2E_CLOSURE_AND_POST_CANARY_DECISION_SUPERLANE_V1"
AUTHORITATIVE_LANE = "B04_R6_CANARY_EVIDENCE_REVIEW_PACKET"
PREVIOUS_LANE = canary.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = canary.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = canary.NEXT_LAWFUL_MOVE

OUTCOME_BOUND = "B04_R6_CANARY_EVIDENCE_REVIEW_PACKET_BOUND__CANARY_EVIDENCE_REVIEW_VALIDATION_NEXT"
OUTCOME_DEFERRED = "B04_R6_CANARY_EVIDENCE_REVIEW_PACKET_DEFERRED__NAMED_PACKET_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_CANARY_EVIDENCE_REVIEW_PACKET_INVALID__REPAIR_OR_CLOSEOUT_REQUIRED"
SELECTED_OUTCOME = OUTCOME_BOUND
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_CANARY_EVIDENCE_REVIEW_PACKET"

RECOMMENDED_NEXT_PATH = "EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT"
ALLOWED_RECOMMENDED_NEXT_PATHS = (
    "RUNTIME_CUTOVER_REVIEW_PACKET_NEXT",
    "EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT",
    "SECOND_CANARY_AUTHORIZATION_PACKET_NEXT",
    "EXTERNAL_AUDIT_DELTA_PACKET_NEXT",
    "REPAIR_OR_CLOSEOUT_NEXT",
    "FORENSIC_CANARY_EVIDENCE_REVIEW_NEXT",
)
VALIDATION_OUTCOMES_PREPARED = (
    "B04_R6_CANARY_EVIDENCE_REVIEW_VALIDATED__RUNTIME_CUTOVER_REVIEW_PACKET_NEXT",
    "B04_R6_CANARY_EVIDENCE_REVIEW_VALIDATED__EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT",
    "B04_R6_CANARY_EVIDENCE_REVIEW_VALIDATED__SECOND_CANARY_AUTHORIZATION_PACKET_NEXT",
    "B04_R6_CANARY_EVIDENCE_REVIEW_VALIDATED__EXTERNAL_AUDIT_DELTA_PACKET_NEXT",
    "B04_R6_CANARY_EVIDENCE_REVIEW_DEFERRED__NAMED_REVIEW_DEFECT_REMAINS",
    "B04_R6_CANARY_EVIDENCE_REVIEW_INVALID__FORENSIC_CANARY_EVIDENCE_REVIEW_NEXT",
)

FORBIDDEN_ACTIONS = (
    "RUNTIME_CUTOVER_AUTHORIZED",
    "ACTIVATION_CUTOVER_EXECUTED",
    "R6_OPEN",
    "LOBE_ESCALATION_AUTHORIZED",
    "PACKAGE_PROMOTION_AUTHORIZED",
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
    "METRIC_CONTRACT_MUTATED",
    "STATIC_COMPARATOR_WEAKENED",
    "CANARY_EVIDENCE_TREATED_AS_PACKAGE_PROMOTION",
)
REASON_CODES = (
    "RC_B04R6_CANARY_EVIDENCE_PACKET_CONTRACT_MISSING",
    "RC_B04R6_CANARY_EVIDENCE_PACKET_MAIN_HEAD_MISMATCH",
    "RC_B04R6_CANARY_EVIDENCE_CANARY_RESULT_MISSING",
    "RC_B04R6_CANARY_EVIDENCE_CANARY_RESULT_NOT_PASSED",
    "RC_B04R6_CANARY_EVIDENCE_CANARY_RECEIPT_MISSING",
    "RC_B04R6_CANARY_EVIDENCE_CASE_MANIFEST_MISSING",
    "RC_B04R6_CANARY_EVIDENCE_SCORECARD_MISSING",
    "RC_B04R6_CANARY_EVIDENCE_DECISION_MATRIX_MISSING",
    "RC_B04R6_CANARY_EVIDENCE_DECISION_MATRIX_UNLAWFUL",
    "RC_B04R6_CANARY_EVIDENCE_BLOCKER_LEDGER_MISSING",
    "RC_B04R6_CANARY_EVIDENCE_PREP_ONLY_AUTHORITY_DRIFT",
    "RC_B04R6_CANARY_EVIDENCE_RUNTIME_CUTOVER_AUTHORIZED",
    "RC_B04R6_CANARY_EVIDENCE_R6_OPEN_DRIFT",
    "RC_B04R6_CANARY_EVIDENCE_LOBE_ESCALATION_DRIFT",
    "RC_B04R6_CANARY_EVIDENCE_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_CANARY_EVIDENCE_COMMERCIAL_CLAIM_DRIFT",
    "RC_B04R6_CANARY_EVIDENCE_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_CANARY_EVIDENCE_TRUST_ZONE_MUTATION",
    "RC_B04R6_CANARY_EVIDENCE_NEXT_MOVE_DRIFT",
)

REVIEW_CATEGORIES = (
    "canary_scope_quality",
    "sample_adequacy",
    "route_distribution_health",
    "fallback_behavior",
    "static_fallback_preservation",
    "abstention_fallback_preservation",
    "null_route_preservation",
    "operator_override_readiness",
    "kill_switch_readiness",
    "rollback_readiness",
    "drift_stability",
    "incident_freeze_cleanliness",
    "trace_completeness",
    "runtime_replayability",
    "external_verifier_readiness",
    "commercial_boundary_safety",
    "runtime_cutover_readiness",
    "expanded_canary_readiness",
    "second_canary_readiness",
    "package_promotion_readiness",
)

CANARY_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in canary.OUTPUTS.items()
    if filename.endswith(".json")
}
CANARY_TEXT_INPUTS = {
    "canary_report": f"KT_PROD_CLEANROOM/reports/{canary.OUTPUTS['report']}",
}
ALL_JSON_INPUTS = {f"canary_{role}": raw for role, raw in CANARY_JSON_INPUTS.items()}
ALL_TEXT_INPUTS = CANARY_TEXT_INPUTS

AUTHORITATIVE_OUTPUT_ROLES = (
    "packet_contract",
    "packet_receipt",
    "evidence_inventory",
    "evidence_scorecard",
    "post_run_decision_matrix",
    "post_canary_blocker_ledger",
    "runtime_cutover_readiness_matrix",
    "expanded_canary_readiness_matrix",
    "second_canary_readiness_matrix",
    "route_distribution_review_contract",
    "fallback_behavior_review_contract",
    "static_fallback_review_contract",
    "abstention_fallback_review_contract",
    "null_route_review_contract",
    "operator_override_review_contract",
    "kill_switch_review_contract",
    "rollback_review_contract",
    "drift_monitoring_review_contract",
    "incident_freeze_review_contract",
    "trace_completeness_review_contract",
    "replay_readiness_review_contract",
    "external_verifier_readiness_review_contract",
    "commercial_claim_boundary_review_contract",
    "package_promotion_blocker_review_contract",
    "no_authorization_drift_receipt",
    "next_lawful_move",
)

PREP_ONLY_OUTPUT_ROLES = (
    "validation_plan",
    "validation_reason_codes",
    "runtime_cutover_review_packet_prep_only_draft",
    "runtime_cutover_scope_contract_prep_only",
    "runtime_cutover_static_fallback_contract_prep_only",
    "runtime_cutover_operator_override_contract_prep_only",
    "runtime_cutover_kill_switch_contract_prep_only",
    "runtime_cutover_rollback_contract_prep_only",
    "runtime_cutover_disqualifier_ledger_prep_only",
    "expanded_canary_authorization_packet_prep_only_draft",
    "second_canary_authorization_packet_prep_only_draft",
    "canary_scope_expansion_matrix_prep_only",
    "second_canary_case_class_matrix_prep_only",
    "package_promotion_blocker_matrix_prep_only",
    "package_promotion_review_packet_prep_only_draft",
    "release_truth_derivation_requirements_prep_only",
    "external_audit_delta_manifest_prep_only",
    "public_verifier_delta_requirements_prep_only",
    "canary_replay_bundle_manifest_prep_only",
    "external_hash_manifest_prep_only",
    "auditor_readme_prep_only",
    "claims_and_boundaries_for_auditors_prep_only",
    "claim_compiler_contract_prep_only",
    "allowed_claims_current_state_prep_only",
    "forbidden_claims_current_state_prep_only",
    "proof_factory_contract_prep_only",
    "lane_spec_schema_v1_prep_only",
    "operator_template_prep_only",
    "validator_template_prep_only",
    "replay_template_prep_only",
    "reason_code_template_prep_only",
    "base_invariant_suite_prep_only",
    "promotion_engine_contract_prep_only",
    "promotion_ladder_prep_only",
    "promotion_receipt_schema_prep_only",
    "demotion_receipt_schema_prep_only",
    "rollback_receipt_schema_prep_only",
    "quarantine_receipt_schema_prep_only",
    "lobe_ratification_factory_contract_prep_only",
    "lobe_role_registry_prep_only",
    "lobe_abi_contract_prep_only",
    "lobe_eval_contract_prep_only",
    "lobe_admissibility_schema_prep_only",
    "lobe_shadow_eval_schema_prep_only",
    "lobe_promotion_schema_prep_only",
    "lobe_retirement_schema_prep_only",
    "lobe_rollback_contract_prep_only",
    "crucible_registry_prep_only",
    "policy_c_pressure_taxonomy_prep_only",
    "epoch_coverage_matrix_prep_only",
    "adapter_registry_prep_only",
    "adapter_lineage_manifest_prep_only",
    "adapter_eval_receipt_schema_prep_only",
    "tournament_protocol_prep_only",
    "merge_law_prep_only",
    "anti_gaming_controls_prep_only",
    "benchmark_constitution_prep_only",
    "competitive_scorecard_schema_prep_only",
    "monolith_vs_static_vs_router_matrix_prep_only",
    "proof_bundle_comparison_prep_only",
    "delivery_quality_comparison_prep_only",
    "negative_result_ledger_prep_only",
    "reaudit_readiness_packet_prep_only",
    "client_wrapper_spec_prep_only",
    "deployment_profiles_prep_only",
    "operator_runbook_delta_prep_only",
    "data_governance_pack_prep_only",
    "commercial_menu_manifest_prep_only",
    "commercial_claim_boundary_prep_only",
    "public_verifier_kit_manifest_prep_only",
    "e2e_closure_campaign_board",
    "kt_future_blocker_register",
    "pipeline_board",
)

OUTPUTS = {
    "packet_contract": "b04_r6_canary_evidence_review_packet_contract.json",
    "packet_receipt": "b04_r6_canary_evidence_review_packet_receipt.json",
    "packet_report": "b04_r6_canary_evidence_review_packet_report.md",
    "evidence_inventory": "b04_r6_canary_evidence_inventory.json",
    "evidence_scorecard": "b04_r6_canary_evidence_scorecard.json",
    "post_run_decision_matrix": "b04_r6_canary_post_run_decision_matrix.json",
    "post_canary_blocker_ledger": "b04_r6_post_canary_blocker_ledger.json",
    "runtime_cutover_readiness_matrix": "b04_r6_runtime_cutover_readiness_matrix.json",
    "expanded_canary_readiness_matrix": "b04_r6_expanded_canary_readiness_matrix.json",
    "second_canary_readiness_matrix": "b04_r6_second_canary_readiness_matrix.json",
    "route_distribution_review_contract": "b04_r6_canary_route_distribution_review_contract.json",
    "fallback_behavior_review_contract": "b04_r6_canary_fallback_behavior_review_contract.json",
    "static_fallback_review_contract": "b04_r6_canary_static_fallback_review_contract.json",
    "abstention_fallback_review_contract": "b04_r6_canary_abstention_fallback_review_contract.json",
    "null_route_review_contract": "b04_r6_canary_null_route_review_contract.json",
    "operator_override_review_contract": "b04_r6_canary_operator_override_review_contract.json",
    "kill_switch_review_contract": "b04_r6_canary_kill_switch_review_contract.json",
    "rollback_review_contract": "b04_r6_canary_rollback_review_contract.json",
    "drift_monitoring_review_contract": "b04_r6_canary_drift_monitoring_review_contract.json",
    "incident_freeze_review_contract": "b04_r6_canary_incident_freeze_review_contract.json",
    "trace_completeness_review_contract": "b04_r6_canary_trace_completeness_review_contract.json",
    "replay_readiness_review_contract": "b04_r6_canary_replay_readiness_review_contract.json",
    "external_verifier_readiness_review_contract": "b04_r6_canary_external_verifier_readiness_review_contract.json",
    "commercial_claim_boundary_review_contract": "b04_r6_canary_commercial_claim_boundary_review_contract.json",
    "package_promotion_blocker_review_contract": "b04_r6_canary_package_promotion_blocker_review_contract.json",
    "no_authorization_drift_receipt": "b04_r6_canary_evidence_no_authorization_drift_receipt.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
    "validation_plan": "b04_r6_canary_evidence_review_validation_plan.json",
    "validation_reason_codes": "b04_r6_canary_evidence_review_validation_reason_codes.json",
    "runtime_cutover_review_packet_prep_only_draft": "b04_r6_runtime_cutover_review_packet_prep_only_draft.json",
    "runtime_cutover_scope_contract_prep_only": "b04_r6_runtime_cutover_scope_contract_prep_only.json",
    "runtime_cutover_static_fallback_contract_prep_only": "b04_r6_runtime_cutover_static_fallback_contract_prep_only.json",
    "runtime_cutover_operator_override_contract_prep_only": "b04_r6_runtime_cutover_operator_override_contract_prep_only.json",
    "runtime_cutover_kill_switch_contract_prep_only": "b04_r6_runtime_cutover_kill_switch_contract_prep_only.json",
    "runtime_cutover_rollback_contract_prep_only": "b04_r6_runtime_cutover_rollback_contract_prep_only.json",
    "runtime_cutover_disqualifier_ledger_prep_only": "b04_r6_runtime_cutover_disqualifier_ledger_prep_only.json",
    "expanded_canary_authorization_packet_prep_only_draft": "b04_r6_expanded_canary_authorization_packet_prep_only_draft.json",
    "second_canary_authorization_packet_prep_only_draft": "b04_r6_second_canary_authorization_packet_prep_only_draft.json",
    "canary_scope_expansion_matrix_prep_only": "b04_r6_canary_scope_expansion_matrix_prep_only.json",
    "second_canary_case_class_matrix_prep_only": "b04_r6_second_canary_case_class_matrix_prep_only.json",
    "package_promotion_blocker_matrix_prep_only": "b04_r6_package_promotion_blocker_matrix_prep_only.json",
    "package_promotion_review_packet_prep_only_draft": "b04_r6_package_promotion_review_packet_prep_only_draft.json",
    "release_truth_derivation_requirements_prep_only": "b04_r6_release_truth_derivation_requirements_prep_only.json",
    "external_audit_delta_manifest_prep_only": "b04_r6_external_audit_delta_manifest_prep_only.json",
    "public_verifier_delta_requirements_prep_only": "b04_r6_public_verifier_delta_requirements_prep_only.json",
    "canary_replay_bundle_manifest_prep_only": "b04_r6_canary_replay_bundle_manifest_prep_only.json",
    "external_hash_manifest_prep_only": "b04_r6_external_hash_manifest_prep_only.json",
    "auditor_readme_prep_only": "b04_r6_auditor_readme_prep_only.md",
    "claims_and_boundaries_for_auditors_prep_only": "b04_r6_claims_and_boundaries_for_auditors_prep_only.md",
    "claim_compiler_contract_prep_only": "kt_claim_compiler_contract_prep_only.json",
    "allowed_claims_current_state_prep_only": "kt_allowed_claims_current_state_prep_only.json",
    "forbidden_claims_current_state_prep_only": "kt_forbidden_claims_current_state_prep_only.json",
    "proof_factory_contract_prep_only": "kt_proof_factory_contract_prep_only.json",
    "lane_spec_schema_v1_prep_only": "kt_lane_spec_schema_v1_prep_only.json",
    "operator_template_prep_only": "kt_operator_template_prep_only.py",
    "validator_template_prep_only": "kt_validator_template_prep_only.py",
    "replay_template_prep_only": "kt_replay_template_prep_only.json",
    "reason_code_template_prep_only": "kt_reason_code_template_prep_only.json",
    "base_invariant_suite_prep_only": "kt_base_invariant_suite_prep_only.py",
    "promotion_engine_contract_prep_only": "kt_promotion_engine_contract_prep_only.json",
    "promotion_ladder_prep_only": "kt_promotion_ladder_prep_only.json",
    "promotion_receipt_schema_prep_only": "kt_promotion_receipt_schema_prep_only.json",
    "demotion_receipt_schema_prep_only": "kt_demotion_receipt_schema_prep_only.json",
    "rollback_receipt_schema_prep_only": "kt_rollback_receipt_schema_prep_only.json",
    "quarantine_receipt_schema_prep_only": "kt_quarantine_receipt_schema_prep_only.json",
    "lobe_ratification_factory_contract_prep_only": "kt_lobe_ratification_factory_contract_prep_only.json",
    "lobe_role_registry_prep_only": "kt_lobe_role_registry_prep_only.json",
    "lobe_abi_contract_prep_only": "kt_lobe_abi_contract_prep_only.json",
    "lobe_eval_contract_prep_only": "kt_lobe_eval_contract_prep_only.json",
    "lobe_admissibility_schema_prep_only": "kt_lobe_admissibility_schema_prep_only.json",
    "lobe_shadow_eval_schema_prep_only": "kt_lobe_shadow_eval_schema_prep_only.json",
    "lobe_promotion_schema_prep_only": "kt_lobe_promotion_schema_prep_only.json",
    "lobe_retirement_schema_prep_only": "kt_lobe_retirement_schema_prep_only.json",
    "lobe_rollback_contract_prep_only": "kt_lobe_rollback_contract_prep_only.json",
    "crucible_registry_prep_only": "kt_crucible_registry_prep_only.json",
    "policy_c_pressure_taxonomy_prep_only": "kt_policy_c_pressure_taxonomy_prep_only.json",
    "epoch_coverage_matrix_prep_only": "kt_epoch_coverage_matrix_prep_only.json",
    "adapter_registry_prep_only": "kt_adapter_registry_prep_only.json",
    "adapter_lineage_manifest_prep_only": "kt_adapter_lineage_manifest_prep_only.json",
    "adapter_eval_receipt_schema_prep_only": "kt_adapter_eval_receipt_schema_prep_only.json",
    "tournament_protocol_prep_only": "kt_tournament_protocol_prep_only.json",
    "merge_law_prep_only": "kt_merge_law_prep_only.json",
    "anti_gaming_controls_prep_only": "kt_anti_gaming_controls_prep_only.json",
    "benchmark_constitution_prep_only": "kt_benchmark_constitution_prep_only.json",
    "competitive_scorecard_schema_prep_only": "kt_competitive_scorecard_schema_prep_only.json",
    "monolith_vs_static_vs_router_matrix_prep_only": "kt_monolith_vs_static_vs_router_matrix_prep_only.json",
    "proof_bundle_comparison_prep_only": "kt_proof_bundle_comparison_prep_only.json",
    "delivery_quality_comparison_prep_only": "kt_delivery_quality_comparison_prep_only.json",
    "negative_result_ledger_prep_only": "kt_negative_result_ledger_prep_only.json",
    "reaudit_readiness_packet_prep_only": "kt_reaudit_readiness_packet_prep_only.json",
    "client_wrapper_spec_prep_only": "kt_client_wrapper_spec_prep_only.json",
    "deployment_profiles_prep_only": "kt_deployment_profiles_prep_only.json",
    "operator_runbook_delta_prep_only": "kt_operator_runbook_delta_prep_only.md",
    "data_governance_pack_prep_only": "kt_data_governance_pack_prep_only.md",
    "commercial_menu_manifest_prep_only": "kt_commercial_menu_manifest_prep_only.json",
    "commercial_claim_boundary_prep_only": "kt_commercial_claim_boundary_prep_only.json",
    "public_verifier_kit_manifest_prep_only": "kt_public_verifier_kit_manifest_prep_only.json",
    "e2e_closure_campaign_board": "kt_e2e_closure_campaign_board.json",
    "kt_future_blocker_register": "kt_future_blocker_register.json",
    "pipeline_board": "b04_r6_pipeline_board.json",
}

PREP_ONLY_INVARIANTS = {
    "authority": "PREP_ONLY",
    "cannot_authorize_runtime_cutover": True,
    "cannot_open_r6": True,
    "cannot_authorize_lobe_escalation": True,
    "cannot_authorize_package_promotion": True,
    "cannot_authorize_commercial_activation_claims": True,
    "cannot_mutate_truth_engine_law": True,
    "cannot_mutate_trust_zone_law": True,
}
AUTHORITY_STATE = {
    "shadow_superiority_passed": True,
    "activation_review_validated": True,
    "limited_runtime_authorization_packet_validated": True,
    "limited_runtime_execution_packet_validated": True,
    "limited_runtime_shadow_runtime_executed": True,
    "runtime_evidence_review_validated": True,
    "canary_authorization_packet_validated": True,
    "canary_execution_packet_validated": True,
    "canary_runtime_executed": True,
    "canary_evidence_review_packet_authored": True,
    "canary_evidence_review_validated": False,
    "runtime_cutover_authorized": False,
    "activation_cutover_executed": False,
    "r6_open": False,
    "lobe_escalation_authorized": False,
    "package_promotion": "DEFERRED",
    "package_promotion_authorized": False,
    "commercial_activation_claim_authorized": False,
    "truth_engine_law_changed": False,
    "trust_zone_law_changed": False,
    "metric_contract_mutated": False,
    "static_comparator_weakened": False,
    "canary_evidence_treated_as_package_promotion": False,
}


def _fail(code: str, detail: str) -> None:
    raise RuntimeError(f"FAIL_CLOSED: {code}: {detail}")


def _ensure_branch_context(root: Path) -> str:
    current_branch = common.git_current_branch_name(root)
    if current_branch not in ALLOWED_BRANCHES:
        allowed = ", ".join(sorted(ALLOWED_BRANCHES))
        raise RuntimeError(f"FAIL_CLOSED: must run on one of: {allowed}; got: {current_branch}")
    if current_branch == "main":
        head = common.git_rev_parse(root, "HEAD")
        origin_main = common.git_rev_parse(root, "origin/main")
        if head != origin_main:
            raise RuntimeError("FAIL_CLOSED: main replay requires local main converged with origin/main")
    return current_branch


def _git_blob_bytes(root: Path, commit: str, raw: str) -> bytes:
    blob_ref = f"{commit}:{raw.replace(chr(92), '/')}"
    result = subprocess.run(["git", "show", blob_ref], cwd=root, capture_output=True, check=True)
    return result.stdout


def _git_blob_sha256(root: Path, commit: str, raw: str) -> str:
    return hashlib.sha256(_git_blob_bytes(root, commit, raw)).hexdigest()


def _load_input(root: Path, raw: str, *, label: str, handoff_git_commit: str, output_names: set[str]) -> Dict[str, Any]:
    if Path(raw).name in output_names:
        try:
            return json.loads(_git_blob_bytes(root, handoff_git_commit, raw).decode("utf-8"))
        except Exception as exc:
            _fail("RC_B04R6_CANARY_EVIDENCE_CANARY_RESULT_MISSING", f"git-bound input {label} missing: {exc}")
    return common.load_json_required(root, raw, label=label)


def _read_text_input(root: Path, raw: str, *, label: str, handoff_git_commit: str, output_names: set[str]) -> str:
    if Path(raw).name in output_names:
        try:
            return _git_blob_bytes(root, handoff_git_commit, raw).decode("utf-8")
        except Exception as exc:
            _fail("RC_B04R6_CANARY_EVIDENCE_CANARY_RECEIPT_MISSING", f"git-bound text input {label} missing: {exc}")
    return common.read_text_required(root, raw, label=label)


def _sha_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _ensure_no_forbidden_authority(payload: Dict[str, Any], *, label: str) -> None:
    forbidden_truths = {
        "runtime_cutover_authorized": "RC_B04R6_CANARY_EVIDENCE_RUNTIME_CUTOVER_AUTHORIZED",
        "activation_cutover_executed": "RC_B04R6_CANARY_EVIDENCE_RUNTIME_CUTOVER_AUTHORIZED",
        "r6_open": "RC_B04R6_CANARY_EVIDENCE_R6_OPEN_DRIFT",
        "lobe_escalation_authorized": "RC_B04R6_CANARY_EVIDENCE_LOBE_ESCALATION_DRIFT",
        "package_promotion_authorized": "RC_B04R6_CANARY_EVIDENCE_PACKAGE_PROMOTION_DRIFT",
        "commercial_activation_claim_authorized": "RC_B04R6_CANARY_EVIDENCE_COMMERCIAL_CLAIM_DRIFT",
        "truth_engine_law_changed": "RC_B04R6_CANARY_EVIDENCE_TRUTH_ENGINE_MUTATION",
        "trust_zone_law_changed": "RC_B04R6_CANARY_EVIDENCE_TRUST_ZONE_MUTATION",
        "metric_contract_mutated": "RC_B04R6_CANARY_EVIDENCE_TRUTH_ENGINE_MUTATION",
        "static_comparator_weakened": "RC_B04R6_CANARY_EVIDENCE_TRUTH_ENGINE_MUTATION",
        "canary_evidence_treated_as_package_promotion": "RC_B04R6_CANARY_EVIDENCE_PACKAGE_PROMOTION_DRIFT",
    }
    for key, code in forbidden_truths.items():
        if payload.get(key) is True or payload.get("authorization_state", {}).get(key) is True:
            _fail(code, f"{label} attempted forbidden authority via {key}")


def _validate_inputs(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    result = payloads["canary_result"]
    next_move = payloads["canary_next_lawful_move"]
    if result.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_CANARY_EVIDENCE_CANARY_RESULT_NOT_PASSED", "prior canary result must be PASSED")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_CANARY_EVIDENCE_NEXT_MOVE_DRIFT", "prior next move must route to canary evidence review")
    if result.get("authorization_state", {}).get("canary_runtime_executed") is not True:
        _fail("RC_B04R6_CANARY_EVIDENCE_CANARY_RESULT_MISSING", "canary runtime must have executed")
    if not payloads["canary_case_manifest"].get("cases"):
        _fail("RC_B04R6_CANARY_EVIDENCE_CASE_MANIFEST_MISSING", "canary case manifest must include cases")
    if "does not authorize runtime cutover" not in texts["canary_report"].lower():
        _fail("RC_B04R6_CANARY_EVIDENCE_RUNTIME_CUTOVER_AUTHORIZED", "canary report must preserve cutover boundary")
    for label, payload in payloads.items():
        _ensure_no_forbidden_authority(payload, label=label)


def _input_bindings(root: Path, *, handoff_git_commit: str, output_names: set[str]) -> Dict[str, str]:
    bindings: Dict[str, str] = {}
    for role, raw in ALL_JSON_INPUTS.items():
        if Path(raw).name in output_names:
            bindings[f"{role}_hash"] = _git_blob_sha256(root, handoff_git_commit, raw)
        else:
            bindings[f"{role}_hash"] = hashlib.sha256((root / raw).read_bytes()).hexdigest()
    for role, raw in ALL_TEXT_INPUTS.items():
        bindings[f"{role}_hash"] = hashlib.sha256((root / raw).read_bytes()).hexdigest()
    return bindings


def _binding_hashes(payloads: Dict[str, Dict[str, Any]], input_bindings: Dict[str, str]) -> Dict[str, str]:
    result_bindings = payloads["canary_result"].get("binding_hashes", {})
    return {
        **input_bindings,
        "validated_canary_execution_packet_hash": result_bindings.get("validated_canary_execution_packet_hash", ""),
        "validated_canary_authorization_hash": result_bindings.get("validated_canary_authorization_hash", ""),
        "runtime_evidence_review_validation_hash": result_bindings.get("runtime_evidence_review_validation_hash", ""),
        "afsh_candidate_hash": result_bindings.get("afsh_candidate_hash", ""),
        "canary_runtime_result_hash": input_bindings["canary_result_hash"],
        "canary_execution_receipt_hash": input_bindings["canary_execution_receipt_hash"],
        "canary_case_manifest_hash": input_bindings["canary_case_manifest_hash"],
        "canary_report_hash": input_bindings["canary_report_hash"],
    }


def _scorecard(payloads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    result = payloads["canary_result"]
    case_manifest = payloads["canary_case_manifest"]
    cases = case_manifest["cases"]
    total_cases = len(cases)
    route_observations = sum(1 for row in cases if row.get("afsh_verdict") == "ROUTE")
    fallback_invocations = sum(1 for row in cases if row.get("fallback_invoked") is True)
    trace_complete = payloads["canary_trace_completeness_receipt"].get("trace_complete_cases", 0)
    categories = []
    category_status = {
        "canary_scope_quality": ("PASS", "Scope stayed limited and operator-observed."),
        "sample_adequacy": ("PARTIAL", "One bounded canary passed; expanded evidence is recommended before cutover."),
        "route_distribution_health": ("PASS", "Route distribution stayed within packet thresholds."),
        "fallback_behavior": ("PASS", "Fallback behavior remained available and accounted for."),
        "static_fallback_preservation": ("PASS", "Static fallback remained preserved."),
        "abstention_fallback_preservation": ("PASS", "Abstention fallback remained preserved."),
        "null_route_preservation": ("PASS", "Null-route controls did not enter canary authority."),
        "operator_override_readiness": ("PASS", "Operator override path remained ready."),
        "kill_switch_readiness": ("PASS", "Kill switch remained ready and was not required."),
        "rollback_readiness": ("PASS", "Rollback remained ready and was not required."),
        "drift_stability": ("PASS", "No drift threshold was exceeded."),
        "incident_freeze_cleanliness": ("PASS", "No incident/freeze condition fired."),
        "trace_completeness": ("PASS", "Canary traces were complete."),
        "runtime_replayability": ("PASS", "Replay receipt was emitted and raw hash-bound artifacts remain required."),
        "external_verifier_readiness": ("PARTIAL", "Verifier readiness exists; public verifier bundle still needs authored packet."),
        "commercial_boundary_safety": ("PASS", "Commercial activation claims remain unauthorized."),
        "runtime_cutover_readiness": ("BLOCKED", "Cutover requires evidence-review validation and a separate cutover review packet."),
        "expanded_canary_readiness": ("READY_FOR_PACKET", "Bounded canary pass justifies authoring expanded-canary authorization packet if validation agrees."),
        "second_canary_readiness": ("READY_FOR_PACKET", "A repeat canary is available as a conservative alternative."),
        "package_promotion_readiness": ("BLOCKED", "Package promotion requires validated canary evidence, external audit, cutover review, and promotion review."),
    }
    for category in REVIEW_CATEGORIES:
        status, rationale = category_status[category]
        categories.append({"category": category, "status": status, "rationale": rationale})
    return {
        "canary_result": result["selected_outcome"],
        "overall_grade": "B_GOOD_BUT_MORE_CANARY_RECOMMENDED",
        "total_cases": total_cases,
        "route_observations": route_observations,
        "fallback_invocations": fallback_invocations,
        "trace_complete_cases": trace_complete,
        "incident_count": len(payloads["canary_incident_freeze_receipt"].get("incident_freeze_triggers", [])),
        "drift_status": payloads["canary_drift_monitoring_receipt"].get("drift_status", "UNKNOWN"),
        "runtime_cutover_review_ready": False,
        "expanded_canary_ready": True,
        "second_canary_ready": True,
        "external_audit_delta_ready": "PARTIAL",
        "package_promotion_ready": False,
        "commercial_claim_status": "BOUNDARY_ONLY",
        "categories": categories,
    }


def _decision_matrix(scorecard: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "decision_matrix_id": "B04_R6_POST_CANARY_DECISION_MATRIX_V1",
        "canary_result": "PASSED",
        "overall_grade": scorecard["overall_grade"],
        "runtime_cutover_review_ready": False,
        "expanded_canary_ready": True,
        "second_canary_ready": True,
        "external_audit_delta_ready": "PARTIAL",
        "package_promotion_ready": False,
        "commercial_claim_status": "BOUNDARY_ONLY",
        "recommended_next_path": RECOMMENDED_NEXT_PATH,
        "blocking_reasons": [
            "runtime_cutover_requires_canary_evidence_review_validation",
            "runtime_cutover_requires_dedicated_cutover_review_packet",
            "package_promotion_requires_external_audit_delta_and_promotion_review",
            "commercial_activation_claims_remain_forbidden",
        ],
        "supporting_evidence": [
            "canary_runtime_result",
            "canary_case_manifest",
            "route_distribution_receipt",
            "fallback_behavior_receipt",
            "trace_completeness_receipt",
            "replay_receipt",
        ],
        "required_repairs_or_next_artifacts": [
            "VALIDATE_B04_R6_CANARY_EVIDENCE_REVIEW_PACKET",
            "AUTHOR_B04_R6_EXPANDED_CANARY_AUTHORIZATION_PACKET if validation accepts this recommendation",
        ],
    }


def _blockers() -> list[Dict[str, Any]]:
    rows = [
        ("B04R6-PCB-0001", "runtime_cutover", "RUNTIME_CUTOVER_REVIEW_PACKET", "canary evidence review is not validated"),
        ("B04R6-PCB-0002", "expanded_canary", "EXPANDED_CANARY_AUTHORIZATION_PACKET", "requires validation of this evidence review recommendation"),
        ("B04R6-PCB-0003", "second_canary", "SECOND_CANARY_AUTHORIZATION_PACKET", "requires validation of this evidence review recommendation"),
        ("B04R6-PCB-0004", "package_promotion", "PACKAGE_PROMOTION_REVIEW_PACKET", "requires validated canary evidence plus external audit and promotion review"),
        ("B04R6-PCB-0005", "external_audit", "EXTERNAL_AUDIT_DELTA_PACKET", "requires replay bundle and public verifier requirements"),
        ("B04R6-PCB-0006", "public_verifier", "PUBLIC_VERIFIER_DELTA", "requires public verifier kit manifest"),
        ("B04R6-PCB-0007", "commercial_claims", "COMMERCIAL_ACTIVATION_CLAIMS", "claims compiler and commercial boundary must remain enforced"),
        ("B04R6-PCB-0008", "operator_readiness", "OPERATOR_RUNBOOK", "operator runbook delta remains prep-only"),
        ("B04R6-PCB-0009", "deployment_profile", "DEPLOYMENT_PROFILE", "deployment profile delta remains prep-only"),
        ("B04R6-PCB-0010", "rollback_proof", "ROLLBACK_PROOF", "rollback evidence must be reviewed before broader runtime authority"),
        ("B04R6-PCB-0011", "data_governance", "DATA_GOVERNANCE_PACK", "data governance pack remains prep-only"),
        ("B04R6-PCB-0012", "secret_distributable_hygiene", "DISTRIBUTABLE_SCAN", "secret/distributable hygiene remains future blocker"),
        ("B04R6-PCB-0013", "benchmark_reaudit_readiness", "REAUDIT_PACKET", "benchmark constitution and re-audit packet remain prep-only"),
    ]
    return [
        {
            "blocker_id": blocker_id,
            "category": category,
            "severity": "BLOCKING",
            "blocks": [blocks],
            "evidence_source": "b04_r6_canary_evidence_scorecard.json",
            "required_repair_or_next_artifact": detail,
            "status": "OPEN",
        }
        for blocker_id, category, blocks, detail in rows
    ]


def _readiness(kind: str, *, ready: bool, recommendation: str, blockers: Sequence[str]) -> Dict[str, Any]:
    return {
        "readiness_matrix_id": f"B04_R6_{kind.upper()}_READINESS_MATRIX_V1",
        "ready": ready,
        "recommendation": recommendation,
        "blockers": list(blockers),
        "runtime_cutover_authorized": False,
        "r6_open": False,
        "package_promotion_authorized": False,
        "commercial_activation_claim_authorized": False,
    }


def _review_contract(base: Dict[str, Any], category: str) -> Dict[str, Any]:
    score = next(row for row in base["scorecard"]["categories"] if row["category"] == category)
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.canary_evidence_review.{category}.v1",
        artifact_id=f"B04_R6_CANARY_{category.upper()}_REVIEW_CONTRACT",
        review_category=category,
        review_status=score["status"],
        review_rationale=score["rationale"],
        authoritative=True,
    )


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str, **extra: Any) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.e2e_closure.{role}.prep_only.v1",
        artifact_id=role.upper(),
        **PREP_ONLY_INVARIANTS,
        status="PREP_ONLY",
        prep_only=True,
        purpose=purpose,
        **extra,
    )


def _campaign_board(base: Dict[str, Any]) -> Dict[str, Any]:
    corridors = [
        ("R6 proof corridor", "CANARY_PASSED__EVIDENCE_REVIEW_NEXT", "AUTHOR_B04_R6_CANARY_EVIDENCE_REVIEW_PACKET", "CANARY_PASSED_ONLY"),
        ("canary corridor", "CANARY_PASSED", "AUTHOR_B04_R6_CANARY_EVIDENCE_REVIEW_PACKET", "CANARY_PASSED_ONLY"),
        ("runtime cutover corridor", "BLOCKED_BY_EVIDENCE_REVIEW_VALIDATION", "VALIDATE_B04_R6_CANARY_EVIDENCE_REVIEW_PACKET", "NO_CUTOVER_CLAIMS"),
        ("package promotion corridor", "BLOCKED", "NONE", "NO_PACKAGE_PROMOTION"),
        ("external audit corridor", "PREP_ONLY", "NONE", "INTERNAL_EVIDENCE_ONLY"),
        ("public verifier corridor", "PREP_ONLY", "NONE", "PUBLIC_VERIFIER_NOT_READY"),
        ("claim compiler corridor", "PREP_ONLY", "NONE", "CLAIM_CEILING_ENFORCED_BY_DRAFT"),
        ("proof factory corridor", "PREP_ONLY", "NONE", "TOOLING_ONLY"),
        ("promotion engine corridor", "PREP_ONLY", "NONE", "NO_PROMOTION_AUTHORITY"),
        ("lobe ratification corridor", "PREP_ONLY", "NONE", "NO_LOBE_ESCALATION"),
        ("adapter / tournament / academy corridor", "PREP_ONLY", "NONE", "NO_ADAPTIVE_ACTIVATION"),
        ("benchmark / re-audit corridor", "PREP_ONLY", "NONE", "NO_EXTERNAL_CLAIM"),
        ("commercial truth plane corridor", "PREP_ONLY", "NONE", "NO_COMMERCIAL_ACTIVATION"),
    ]
    return _prep_only(
        base,
        role="kt_e2e_closure_campaign_board",
        purpose="Campaign command center across proof, runtime, audit, factory, benchmark, and commercial corridors.",
        corridors=[
            {
                "corridor": name,
                "status": status,
                "authoritative_next": authoritative_next,
                "blocked_authorities": [
                    "RUNTIME_CUTOVER_AUTHORIZED",
                    "R6_OPEN",
                    "PACKAGE_PROMOTION_AUTHORIZED",
                    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
                ],
                "claim_ceiling": claim_ceiling,
                "prep_only_tracks": sorted(PREP_ONLY_OUTPUT_ROLES),
                "blockers": [row["blocker_id"] for row in base["blockers"]],
                "receipts": sorted(AUTHORITATIVE_OUTPUT_ROLES),
            }
            for name, status, authoritative_next, claim_ceiling in corridors
        ],
    )


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    current_branch: str,
    input_bindings: Dict[str, str],
    binding_hashes: Dict[str, str],
    scorecard: Dict[str, Any],
    decision_matrix: Dict[str, Any],
    blockers: list[Dict[str, Any]],
    trust_zone_validation: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        **AUTHORITY_STATE,
        "superlane_id": SUPERLANE_ID,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "previous_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "recommended_next_path": decision_matrix["recommended_next_path"],
        "allowed_outcomes": [OUTCOME_BOUND, OUTCOME_DEFERRED, OUTCOME_INVALID],
        "allowed_recommended_next_paths": list(ALLOWED_RECOMMENDED_NEXT_PATHS),
        "validation_outcomes_prepared": list(VALIDATION_OUTCOMES_PREPARED),
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "reason_codes": list(REASON_CODES),
        "generated_utc": generated_utc,
        "current_branch": current_branch,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "authorization_state": dict(AUTHORITY_STATE),
        "input_bindings": input_bindings,
        "binding_hashes": binding_hashes,
        "scorecard": scorecard,
        "decision_matrix": decision_matrix,
        "blockers": blockers,
        "trust_zone_validation": trust_zone_validation,
    }


def _artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {**base, "schema_id": schema_id, "artifact_id": artifact_id, **extra}


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    outputs: Dict[str, Any] = {
        "packet_contract": _artifact(base, schema_id="kt.b04_r6.canary_evidence_review.packet.v1", artifact_id="B04_R6_CANARY_EVIDENCE_REVIEW_PACKET"),
        "packet_receipt": _artifact(base, schema_id="kt.b04_r6.canary_evidence_review.receipt.v1", artifact_id="B04_R6_CANARY_EVIDENCE_REVIEW_PACKET_RECEIPT", receipt_role="packet_authored"),
        "evidence_inventory": _artifact(base, schema_id="kt.b04_r6.canary_evidence_review.inventory.v1", artifact_id="B04_R6_CANARY_EVIDENCE_INVENTORY", evidence_inputs=sorted(ALL_JSON_INPUTS), text_inputs=sorted(ALL_TEXT_INPUTS)),
        "evidence_scorecard": _artifact(base, schema_id="kt.b04_r6.canary_evidence_review.scorecard.v1", artifact_id="B04_R6_CANARY_EVIDENCE_SCORECARD", scorecard=base["scorecard"]),
        "post_run_decision_matrix": _artifact(base, schema_id="kt.b04_r6.canary_evidence_review.decision_matrix.v1", artifact_id="B04_R6_CANARY_POST_RUN_DECISION_MATRIX", decision_matrix=base["decision_matrix"]),
        "post_canary_blocker_ledger": _artifact(base, schema_id="kt.b04_r6.canary_evidence_review.blocker_ledger.v1", artifact_id="B04_R6_POST_CANARY_BLOCKER_LEDGER", blockers=base["blockers"]),
        "runtime_cutover_readiness_matrix": _artifact(base, schema_id="kt.b04_r6.runtime_cutover.readiness_matrix.v1", artifact_id="B04_R6_RUNTIME_CUTOVER_READINESS_MATRIX", readiness=_readiness("runtime_cutover", ready=False, recommendation="BLOCKED_UNTIL_EVIDENCE_REVIEW_VALIDATION_AND_CUTOVER_REVIEW_PACKET", blockers=["canary_evidence_review_not_validated", "cutover_review_packet_missing"])),
        "expanded_canary_readiness_matrix": _artifact(base, schema_id="kt.b04_r6.expanded_canary.readiness_matrix.v1", artifact_id="B04_R6_EXPANDED_CANARY_READINESS_MATRIX", readiness=_readiness("expanded_canary", ready=True, recommendation="READY_FOR_AUTHORIZATION_PACKET_IF_VALIDATED", blockers=["canary_evidence_review_validation_pending"])),
        "second_canary_readiness_matrix": _artifact(base, schema_id="kt.b04_r6.second_canary.readiness_matrix.v1", artifact_id="B04_R6_SECOND_CANARY_READINESS_MATRIX", readiness=_readiness("second_canary", ready=True, recommendation="READY_FOR_AUTHORIZATION_PACKET_IF_VALIDATED", blockers=["canary_evidence_review_validation_pending"])),
        "no_authorization_drift_receipt": _artifact(base, schema_id="kt.b04_r6.canary_evidence_review.no_authorization_drift.v1", artifact_id="B04_R6_CANARY_EVIDENCE_NO_AUTHORIZATION_DRIFT_RECEIPT", no_authorization_drift=True),
        "next_lawful_move": _artifact(base, schema_id="kt.operator.b04_r6_next_lawful_move_receipt.v35", artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT", verdict="NEXT_LAWFUL_MOVE_SET"),
    }
    review_map = {
        "route_distribution_review_contract": "route_distribution_health",
        "fallback_behavior_review_contract": "fallback_behavior",
        "static_fallback_review_contract": "static_fallback_preservation",
        "abstention_fallback_review_contract": "abstention_fallback_preservation",
        "null_route_review_contract": "null_route_preservation",
        "operator_override_review_contract": "operator_override_readiness",
        "kill_switch_review_contract": "kill_switch_readiness",
        "rollback_review_contract": "rollback_readiness",
        "drift_monitoring_review_contract": "drift_stability",
        "incident_freeze_review_contract": "incident_freeze_cleanliness",
        "trace_completeness_review_contract": "trace_completeness",
        "replay_readiness_review_contract": "runtime_replayability",
        "external_verifier_readiness_review_contract": "external_verifier_readiness",
        "commercial_claim_boundary_review_contract": "commercial_boundary_safety",
        "package_promotion_blocker_review_contract": "package_promotion_readiness",
    }
    for role, category in review_map.items():
        outputs[role] = _review_contract(base, category)
    outputs["validation_plan"] = _prep_only(
        base,
        role="b04_r6_canary_evidence_review_validation_plan",
        purpose="Prepare canonical validation of the canary evidence review packet.",
        validation_requirements=list(REVIEW_CATEGORIES),
        possible_validated_outcomes=list(VALIDATION_OUTCOMES_PREPARED),
    )
    outputs["validation_reason_codes"] = _prep_only(
        base,
        role="b04_r6_canary_evidence_review_validation_reason_codes",
        purpose="Reason-code taxonomy for future canary evidence review validation.",
        reason_codes=list(REASON_CODES),
    )
    outputs.update(_prep_outputs(base))
    return outputs


def _prep_outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    allowed_claims = [
        "AFSH passed limited-runtime canary under bounded packet law.",
        "Canary evidence review is the next lawful move.",
        "Runtime cutover remains unauthorized.",
        "R6 remains closed.",
        "Package promotion remains unauthorized.",
        "Commercial activation claims remain unauthorized.",
    ]
    forbidden_claims = [
        "AFSH is live.",
        "R6 is open.",
        "The router is in production.",
        "Package is promotion-ready.",
        "Commercial activation is authorized.",
    ]
    outputs: Dict[str, Any] = {
        "e2e_closure_campaign_board": _campaign_board(base),
        "kt_future_blocker_register": _prep_only(base, role="kt_future_blocker_register", purpose="Campaign-level future blocker register.", blockers=base["blockers"]),
        "pipeline_board": _prep_only(base, role="b04_r6_pipeline_board", purpose="B04 R6 pipeline board update.", lanes=[
            {"lane": "RUN_B04_R6_LIMITED_RUNTIME_CANARY", "status": "PASSED", "authoritative": False},
            {"lane": "AUTHOR_B04_R6_CANARY_EVIDENCE_REVIEW_PACKET", "status": "CURRENT_BOUND", "authoritative": True},
            {"lane": NEXT_LAWFUL_MOVE, "status": "NEXT", "authoritative": True},
            {"lane": "RUNTIME_CUTOVER", "status": "BLOCKED", "authoritative": False},
            {"lane": "PACKAGE_PROMOTION", "status": "BLOCKED", "authoritative": False},
        ]),
        "claim_compiler_contract_prep_only": _prep_only(base, role="kt_claim_compiler_contract", purpose="Prep-only claim compiler contract deriving claim ceilings from receipts.", allowed_claims=allowed_claims, forbidden_claims=forbidden_claims),
        "allowed_claims_current_state_prep_only": _prep_only(base, role="kt_allowed_claims_current_state", purpose="Allowed current-state claims.", allowed_claims=allowed_claims),
        "forbidden_claims_current_state_prep_only": _prep_only(base, role="kt_forbidden_claims_current_state", purpose="Forbidden current-state claims.", forbidden_claims=forbidden_claims),
    }
    for role in PREP_ONLY_OUTPUT_ROLES:
        if role in outputs or role in {"validation_plan", "validation_reason_codes"}:
            continue
        outputs[role] = _prep_only(base, role=role, purpose=f"Prep-only scaffold for {role.replace('_', ' ')}.")
    return outputs


def _report_text(contract: Dict[str, Any]) -> str:
    return (
        "# B04 R6 Canary Evidence Review Packet\n\n"
        f"Outcome: {contract['selected_outcome']}\n\n"
        f"Next lawful move: {contract['next_lawful_move']}\n\n"
        f"Decision-matrix recommendation: {contract['recommended_next_path']}\n\n"
        "The limited-runtime canary passed. This packet binds the canary evidence, emits a scorecard, blocker "
        "ledger, readiness matrices, and campaign prep-only scaffolds. The evidence is good enough to recommend "
        "expanded-canary authorization packet authorship after validation, but it does not authorize runtime "
        "cutover, R6 opening, lobe escalation, package promotion, commercial activation claims, truth/trust law "
        "mutation, metric widening, or comparator weakening.\n"
    )


def run(*, reports_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    reports_root = reports_root or root / "KT_PROD_CLEANROOM" / "reports"
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")
    current_branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 canary evidence review packet")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if current_branch != "main" else "HEAD")
    handoff_git_commit = current_main_head if current_branch != "main" else head
    output_names = set(OUTPUTS.values())
    payloads = {
        role: _load_input(root, raw, label=role, handoff_git_commit=handoff_git_commit, output_names=output_names)
        for role, raw in ALL_JSON_INPUTS.items()
    }
    texts = {
        role: _read_text_input(root, raw, label=role, handoff_git_commit=handoff_git_commit, output_names=output_names)
        for role, raw in ALL_TEXT_INPUTS.items()
    }
    _validate_inputs(payloads, texts)
    fresh_trust_validation = validate_trust_zones(root=root)
    if fresh_trust_validation.get("status") != "PASS" or fresh_trust_validation.get("failures"):
        _fail("RC_B04R6_CANARY_EVIDENCE_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass")

    input_bindings = _input_bindings(root, handoff_git_commit=handoff_git_commit, output_names=output_names)
    scorecard = _scorecard(payloads)
    decision_matrix = _decision_matrix(scorecard)
    blockers = _blockers()
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        current_branch=current_branch,
        input_bindings=input_bindings,
        binding_hashes=_binding_hashes(payloads, input_bindings),
        scorecard=scorecard,
        decision_matrix=decision_matrix,
        blockers=blockers,
        trust_zone_validation=fresh_trust_validation,
    )
    output_payloads = _outputs(base)
    contract = output_payloads["packet_contract"]
    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "packet_report":
            path.write_text(_report_text(contract), encoding="utf-8", newline="\n")
        elif filename.endswith(".md"):
            path.write_text(
                (
                    f"# {role.replace('_', ' ').title()}\n\n"
                    "PREP_ONLY. This artifact cannot authorize runtime cutover, R6 opening, package promotion, "
                    "or commercial activation claims.\n\n"
                    "```json\n"
                    f"{json.dumps(PREP_ONLY_INVARIANTS, indent=2, sort_keys=True)}\n"
                    "```\n"
                ),
                encoding="utf-8",
                newline="\n",
            )
        elif filename.endswith(".py"):
            path.write_text(
                (
                    '"""PREP_ONLY template artifact. Cannot authorize runtime cutover, R6 opening, package '
                    'promotion, or commercial activation claims."""\n\n'
                    f"PREP_ONLY_INVARIANTS = {json.dumps(PREP_ONLY_INVARIANTS, indent=2, sort_keys=True)}\n"
                ),
                encoding="utf-8",
                newline="\n",
            )
        else:
            write_json_stable(path, output_payloads[role])
    return contract


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Author B04 R6 canary evidence review packet and E2E decision superlane.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(reports_root=reports_root)
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
