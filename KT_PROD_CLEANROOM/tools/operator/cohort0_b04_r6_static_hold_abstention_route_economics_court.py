from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-static-hold-abstention-route-economics-court"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT"
PREVIOUS_LANE = "B04_R6_NEW_BLIND_INPUT_UNIVERSE_VALIDATION"

EXPECTED_PREVIOUS_OUTCOME = "B04_R6_NEW_BLIND_UNIVERSE_VALIDATED__STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT_NEXT"
EXPECTED_PREVIOUS_NEXT_MOVE = "AUTHOR_B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT"
OUTCOME_BOUND = "B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT_BOUND__COURT_VALIDATION_NEXT"
OUTCOME_DEFERRED = "B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT_DEFERRED__NAMED_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT_INVALID__REPAIR_OR_CLOSEOUT_REQUIRED"
SELECTED_OUTCOME = OUTCOME_BOUND
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT"

SELECTED_ARCHITECTURE_ID = "AFSH-2S-GUARD"
SELECTED_ARCHITECTURE_NAME = "Abstention-First Static-Hold Two-Stage Guarded Router"
UNIVERSE_ID = "B04_R6_AFSH_BLIND_UNIVERSE_1"
CASE_PREFIX = "B04R6-AFSH-BU1-"
EXPECTED_CASE_COUNT = 18

VERDICT_MODES = ("STATIC_HOLD", "ABSTAIN", "NULL_ROUTE", "ROUTE_ELIGIBLE")
ROUTE_VALUE_TERMS = (
    "expected_quality_delta",
    "expected_governance_benefit",
    "expected_proof_burden_reduction",
    "expected_error_surface_reduction",
    "wrong_route_cost",
    "wrong_static_hold_cost_if_applicable",
    "overrouting_penalty",
    "abstention_violation_penalty",
    "null_route_violation_penalty",
    "mirror_masked_instability_penalty",
    "trace_complexity_penalty",
    "trust_zone_risk_penalty",
)
ROUTE_ELIGIBILITY_GATES = (
    "route_value > frozen_route_threshold",
    "static_hold_dominance == false",
    "abstention_required == false",
    "null_route_required == false",
    "trust_zone_pass == true",
    "mirror_masked_stability == pass",
    "trace_requirements_satisfied == true",
    "comparator_not_weakened == true",
    "metric_not_widened == true",
    "no_authorization_drift == true",
)

FORBIDDEN_CLAIMS = [
    "afsh_source_packet_authorized",
    "afsh_candidate_generation_authorized",
    "afsh_candidate_training_authorized",
    "shadow_screen_packet_authorized",
    "shadow_screen_execution_authorized",
    "r6_open",
    "learned_router_superiority_earned",
    "activation_review_authorized",
    "runtime_cutover_authorized",
    "lobe_escalation_authorized",
    "package_promotion_authorized",
]

FORBIDDEN_TRUE_KEYS = [
    "r6_authorized",
    "r6_open",
    "router_generation_authorized",
    "candidate_generation_authorized",
    "candidate_training_authorized",
    "afsh_source_packet_authorized",
    "afsh_candidate_generation_authorized",
    "afsh_candidate_training_authorized",
    "shadow_screen_authorized",
    "new_shadow_screen_authorized",
    "shadow_screen_packet_authorized",
    "shadow_screen_execution_authorized",
    "learned_router_superiority_earned",
    "activation_review_authorized",
    "runtime_cutover_authorized",
    "learned_router_activated",
    "learned_router_cutover_authorized",
    "multi_lobe_authorized",
    "lobe_escalation_authorized",
    "package_promotion_authorized",
    "package_promotion_approved",
    "commercial_broadening",
]

REASON_CODES: Dict[str, list[str]] = {
    "STATIC_HOLD": [
        "RC_B04R6_COURT_STATIC_DEFAULT",
        "RC_B04R6_COURT_STATIC_COMPARATOR_DOMINANT",
        "RC_B04R6_COURT_STATIC_PROOF_BURDEN_LOWER",
        "RC_B04R6_COURT_STATIC_ROUTE_VALUE_BELOW_THRESHOLD",
        "RC_B04R6_COURT_STATIC_MIRROR_MASKED_RISK",
        "RC_B04R6_COURT_STATIC_WRONG_ROUTE_COST_HIGH",
        "RC_B04R6_COURT_STATIC_CONFIDENCE_NON_MONOTONIC",
        "RC_B04R6_COURT_STATIC_TRACE_COMPLEXITY_TOO_HIGH",
    ],
    "ABSTAIN": [
        "RC_B04R6_COURT_ABSTAIN_BOUNDARY_UNCLEAR",
        "RC_B04R6_COURT_ABSTAIN_TRUST_ZONE_UNCERTAIN",
        "RC_B04R6_COURT_ABSTAIN_CALIBRATION_WEAK",
        "RC_B04R6_COURT_ABSTAIN_CONTRADICTION_UNRESOLVED",
        "RC_B04R6_COURT_ABSTAIN_CONTEXT_UNAVAILABLE",
        "RC_B04R6_COURT_ABSTAIN_HIDDEN_LABEL_DEPENDENCY",
        "RC_B04R6_COURT_ABSTAIN_OUTCOME_DEPENDENCY",
        "RC_B04R6_COURT_ABSTAIN_UNAUTHORIZED_BEHAVIOR_RISK",
    ],
    "NULL_ROUTE": [
        "RC_B04R6_COURT_NULL_ROUTE_CONTROL",
        "RC_B04R6_COURT_NULL_ROUTE_SURFACE_TEMPTATION",
        "RC_B04R6_COURT_NULL_ROUTE_NO_LAWFUL_SPECIALIST",
        "RC_B04R6_COURT_NULL_ROUTE_COSMETIC_MOVEMENT",
        "RC_B04R6_COURT_NULL_ROUTE_TRACE_WITHOUT_VALUE",
    ],
    "ROUTE_ELIGIBLE": [
        "RC_B04R6_COURT_ROUTE_ELIGIBLE_VALUE_CLEARS_THRESHOLD",
        "RC_B04R6_COURT_ROUTE_ELIGIBLE_STATIC_NOT_DOMINANT",
        "RC_B04R6_COURT_ROUTE_ELIGIBLE_ABSTENTION_NOT_REQUIRED",
        "RC_B04R6_COURT_ROUTE_ELIGIBLE_NULL_ROUTE_NOT_REQUIRED",
        "RC_B04R6_COURT_ROUTE_ELIGIBLE_WRONG_ROUTE_COST_BOUNDED",
        "RC_B04R6_COURT_ROUTE_ELIGIBLE_PROOF_BURDEN_JUSTIFIED",
        "RC_B04R6_COURT_ROUTE_ELIGIBLE_TRACE_READY",
    ],
    "TERMINAL_DEFECT": [
        "RC_B04R6_COURT_DEFECT_ROUTE_ELIGIBLE_AUTHORIZES_EXECUTION",
        "RC_B04R6_COURT_DEFECT_CANDIDATE_GENERATION_DRIFT",
        "RC_B04R6_COURT_DEFECT_SHADOW_SCREEN_DRIFT",
        "RC_B04R6_COURT_DEFECT_R6_OPEN_DRIFT",
        "RC_B04R6_COURT_DEFECT_ACTIVATION_DRIFT",
        "RC_B04R6_COURT_DEFECT_PACKAGE_PROMOTION_DRIFT",
        "RC_B04R6_COURT_DEFECT_METRIC_WIDENING",
        "RC_B04R6_COURT_DEFECT_COMPARATOR_WEAKENING",
        "RC_B04R6_COURT_DEFECT_TRUTH_ENGINE_MUTATION",
        "RC_B04R6_COURT_DEFECT_TRUST_ZONE_MUTATION",
        "RC_B04R6_COURT_DEFECT_OLD_UNIVERSE_FRESH_PROOF_DRIFT",
        "RC_B04R6_COURT_DEFECT_NEXT_MOVE_DRIFT",
    ],
}

INPUTS = {
    "validation_contract": "KT_PROD_CLEANROOM/reports/b04_r6_new_blind_input_universe_validation_contract.json",
    "validation_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_new_blind_input_universe_validation_receipt.json",
    "case_manifest": "KT_PROD_CLEANROOM/reports/b04_r6_blind_universe_case_manifest.json",
    "case_manifest_validation": "KT_PROD_CLEANROOM/reports/b04_r6_blind_universe_case_manifest_validation_receipt.json",
    "holdout_validation": "KT_PROD_CLEANROOM/reports/b04_r6_blind_universe_holdout_validation_receipt.json",
    "leakage_validation": "KT_PROD_CLEANROOM/reports/b04_r6_blind_universe_leakage_validation_receipt.json",
    "control_sibling_validation": "KT_PROD_CLEANROOM/reports/b04_r6_blind_universe_control_sibling_validation_receipt.json",
    "diagnostic_only_validation": "KT_PROD_CLEANROOM/reports/b04_r6_blind_universe_diagnostic_only_validation_receipt.json",
    "trust_zone_validation": "KT_PROD_CLEANROOM/reports/b04_r6_blind_universe_trust_zone_validation_receipt.json",
    "no_authorization_drift": "KT_PROD_CLEANROOM/reports/b04_r6_blind_universe_no_authorization_drift_receipt.json",
    "replay_validation": "KT_PROD_CLEANROOM/reports/b04_r6_blind_universe_replay_validation_receipt.json",
    "previous_next_lawful_move": "KT_PROD_CLEANROOM/reports/b04_r6_next_lawful_move_receipt.json",
}

PREP_INPUTS = {
    "static_hold_draft": "KT_PROD_CLEANROOM/reports/b04_r6_static_hold_court_contract_draft.json",
    "abstention_registry_draft": "KT_PROD_CLEANROOM/reports/b04_r6_abstention_control_registry_draft.json",
    "route_economics_draft": "KT_PROD_CLEANROOM/reports/b04_r6_route_economics_matrix_draft.json",
    "afsh_interface_draft": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_router_interface_contract_draft.json",
    "afsh_trace_schema_draft": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_trace_schema_draft.json",
}

REFERENCE_INPUTS = {
    "trust_zone_registry": "KT_PROD_CLEANROOM/governance/trust_zone_registry.json",
    "canonical_scope_manifest": "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json",
}

OUTPUTS = {
    "court_contract": "b04_r6_static_hold_abstention_route_economics_court_contract.json",
    "court_receipt": "b04_r6_static_hold_abstention_route_economics_court_receipt.json",
    "court_report": "b04_r6_static_hold_abstention_route_economics_court_report.md",
    "static_hold_control": "b04_r6_static_hold_control_contract.json",
    "abstention_registry": "b04_r6_abstention_control_registry.json",
    "null_route_control": "b04_r6_null_route_control_contract.json",
    "route_economics": "b04_r6_route_economics_matrix.json",
    "wrong_route_cost": "b04_r6_wrong_route_cost_contract.json",
    "wrong_static_hold_cost": "b04_r6_wrong_static_hold_cost_contract.json",
    "proof_burden_delta": "b04_r6_proof_burden_delta_contract.json",
    "threshold_profile": "b04_r6_route_value_threshold_profile.json",
    "reason_codes": "b04_r6_court_reason_code_taxonomy.json",
    "disqualifier_ledger": "b04_r6_court_disqualifier_ledger.json",
    "no_authorization_drift": "b04_r6_court_no_authorization_drift_receipt.json",
    "validation_plan": "b04_r6_static_hold_abstention_route_economics_court_validation_plan.json",
    "validation_reason_codes": "b04_r6_static_hold_abstention_route_economics_court_validation_reason_codes.json",
    "validation_test_plan": "b04_r6_static_hold_abstention_route_economics_court_validation_test_plan.md",
    "afsh_source_packet_prep": "b04_r6_afsh_implementation_source_packet_prep_only_draft.json",
    "afsh_features_prep": "b04_r6_afsh_allowed_forbidden_features_prep_only_draft.json",
    "afsh_trace_prep": "b04_r6_afsh_trace_schema_prep_only_draft.json",
    "afsh_provenance_prep": "b04_r6_afsh_provenance_matrix_prep_only_draft.json",
    "future_blocker_register": "b04_r6_future_blocker_register.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
}


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


def _ensure_branch_context(root: Path) -> str:
    current_branch = common.git_current_branch_name(root)
    if current_branch not in ALLOWED_BRANCHES:
        allowed = ", ".join(sorted(ALLOWED_BRANCHES))
        raise RuntimeError(f"FAIL_CLOSED: must run on one of: {allowed}; got: {current_branch}")
    if current_branch == "main":
        head = common.git_rev_parse(root, "HEAD")
        origin_main = common.git_rev_parse(root, "origin/main")
        if head != origin_main:
            raise RuntimeError(
                "FAIL_CLOSED: main replay requires local main converged with origin/main; "
                f"HEAD={head}; origin/main={origin_main}"
            )
    return current_branch


def _input_hashes(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in sorted({**INPUTS, **PREP_INPUTS, **REFERENCE_INPUTS}.items()):
        path = root / raw
        if not path.is_file():
            raise RuntimeError(f"FAIL_CLOSED: missing required input: {raw}")
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    return rows


def _ensure_false_if_present(payload: Dict[str, Any], key: str, *, label: str) -> None:
    if key in payload and payload.get(key) is not False:
        raise RuntimeError(f"FAIL_CLOSED: {label} drifted: {key} must remain false")


def _ensure_common_boundary(payload: Dict[str, Any], *, label: str, prep_only_allowed: bool = True) -> None:
    allowed_statuses = {"PASS", "FROZEN_PACKET"}
    if prep_only_allowed:
        allowed_statuses.add("PREP_ONLY")
    if str(payload.get("status", "")).strip() not in allowed_statuses:
        raise RuntimeError(f"FAIL_CLOSED: {label} must have status in {sorted(allowed_statuses)}")
    for key in FORBIDDEN_TRUE_KEYS:
        _ensure_false_if_present(payload, key, label=label)
    if payload.get("package_promotion_remains_deferred") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve package promotion deferral")
    if payload.get("truth_engine_derivation_law_unchanged") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve truth-engine law")
    if payload.get("trust_zone_law_unchanged") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve trust-zone law")


def _pass_row(check_id: str, reason_code: str, detail: str) -> Dict[str, str]:
    return {"check_id": check_id, "status": "PASS", "reason_code": reason_code, "detail": detail}


def _require_inputs(payloads: Dict[str, Dict[str, Any]], prep_payloads: Dict[str, Dict[str, Any]]) -> None:
    for label, payload in payloads.items():
        _ensure_common_boundary(payload, label=label)
    for label, payload in prep_payloads.items():
        _ensure_common_boundary(payload, label=label)
        if str(payload.get("status", "")).strip() != "PREP_ONLY":
            raise RuntimeError(f"FAIL_CLOSED: {label} must remain PREP_ONLY")

    receipt = payloads["validation_receipt"]
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: blind-universe validation selected outcome is not the expected predecessor")
    if receipt.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        raise RuntimeError("FAIL_CLOSED: predecessor next lawful move does not authorize this court")
    if receipt.get("bound_universe_validated") is not True:
        raise RuntimeError("FAIL_CLOSED: bound blind universe must be validated before route-value law")
    if receipt.get("case_count") != EXPECTED_CASE_COUNT:
        raise RuntimeError("FAIL_CLOSED: validated blind universe must bind 18 cases")
    if receipt.get("selected_architecture_id") != SELECTED_ARCHITECTURE_ID:
        raise RuntimeError("FAIL_CLOSED: selected architecture must remain AFSH-2S-GUARD")
    if int(receipt.get("failure_count", 1)) != 0:
        raise RuntimeError("FAIL_CLOSED: blind-universe validation failures remain")

    handoff = payloads["previous_next_lawful_move"]
    if handoff.get("authoritative_lane") != PREVIOUS_LANE:
        raise RuntimeError("FAIL_CLOSED: previous next lawful move receipt lane drifted")
    if handoff.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: previous next lawful move receipt outcome drifted")
    if handoff.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        raise RuntimeError("FAIL_CLOSED: previous next lawful move receipt does not authorize this court")

    manifest = payloads["case_manifest"]
    cases = manifest.get("cases", [])
    if not isinstance(cases, list) or len(cases) != EXPECTED_CASE_COUNT:
        raise RuntimeError("FAIL_CLOSED: case manifest must contain exactly 18 cases")
    case_ids = [str(case.get("case_id", "")) for case in cases if isinstance(case, dict)]
    if len(case_ids) != EXPECTED_CASE_COUNT or len(set(case_ids)) != EXPECTED_CASE_COUNT:
        raise RuntimeError("FAIL_CLOSED: case IDs must be present and unique")
    if any(not case_id.startswith(CASE_PREFIX) for case_id in case_ids):
        raise RuntimeError("FAIL_CLOSED: case IDs must stay in the B04R6-AFSH-BU1 namespace")


def _validation_rows() -> list[Dict[str, str]]:
    return [
        _pass_row("previous_blind_universe_validated", "RC_B04R6_COURT_DEFECT_NEXT_MOVE_DRIFT", "validated universe authorizes court authoring only"),
        _pass_row("selected_afsh_architecture_bound", "RC_B04R6_COURT_DEFECT_NEXT_MOVE_DRIFT", "AFSH-2S-GUARD remains selected architecture"),
        _pass_row("validated_18_case_universe_bound", "RC_B04R6_COURT_DEFECT_OLD_UNIVERSE_FRESH_PROOF_DRIFT", "18 fresh B04R6-AFSH-BU1 cases remain bound"),
        _pass_row("static_hold_default_positive_verdict", "RC_B04R6_COURT_STATIC_DEFAULT", "STATIC_HOLD is default and positive"),
        _pass_row("abstain_positive_success_verdict", "RC_B04R6_COURT_ABSTAIN_BOUNDARY_UNCLEAR", "ABSTAIN is a positive success verdict"),
        _pass_row("null_route_anti_overrouting_control", "RC_B04R6_COURT_NULL_ROUTE_CONTROL", "NULL_ROUTE is anti-overrouting control"),
        _pass_row("route_eligible_non_executing_precondition", "RC_B04R6_COURT_DEFECT_ROUTE_ELIGIBLE_AUTHORIZES_EXECUTION", "ROUTE_ELIGIBLE is non-executing only"),
        _pass_row("route_value_formula_complete", "RC_B04R6_COURT_ROUTE_ELIGIBLE_VALUE_CLEARS_THRESHOLD", "route value formula includes required benefits and penalties"),
        _pass_row("wrong_route_cost_bound", "RC_B04R6_COURT_STATIC_WRONG_ROUTE_COST_HIGH", "wrong-route cost is explicit"),
        _pass_row("wrong_static_hold_cost_bound", "RC_B04R6_COURT_ROUTE_ELIGIBLE_WRONG_ROUTE_COST_BOUNDED", "wrong-static-hold cost is tracked"),
        _pass_row("proof_burden_delta_bound", "RC_B04R6_COURT_ROUTE_ELIGIBLE_PROOF_BURDEN_JUSTIFIED", "proof-burden delta is explicit"),
        _pass_row("threshold_profile_frozen", "RC_B04R6_COURT_STATIC_ROUTE_VALUE_BELOW_THRESHOLD", "thresholds are frozen before candidate generation"),
        _pass_row("metric_widening_forbidden", "RC_B04R6_COURT_DEFECT_METRIC_WIDENING", "metric widening is forbidden"),
        _pass_row("comparator_weakening_forbidden", "RC_B04R6_COURT_DEFECT_COMPARATOR_WEAKENING", "comparator weakening is forbidden"),
        _pass_row("old_universes_diagnostic_only", "RC_B04R6_COURT_DEFECT_OLD_UNIVERSE_FRESH_PROOF_DRIFT", "old R01-R04 and v2 universes remain diagnostic-only"),
        _pass_row("no_generation_authorization", "RC_B04R6_COURT_DEFECT_CANDIDATE_GENERATION_DRIFT", "candidate generation remains unauthorized"),
        _pass_row("no_shadow_screen_authorization", "RC_B04R6_COURT_DEFECT_SHADOW_SCREEN_DRIFT", "shadow screen remains unauthorized"),
        _pass_row("no_r6_open_drift", "RC_B04R6_COURT_DEFECT_R6_OPEN_DRIFT", "R6 remains closed"),
        _pass_row("no_activation_drift", "RC_B04R6_COURT_DEFECT_ACTIVATION_DRIFT", "activation and cutover remain false"),
        _pass_row("no_package_promotion_drift", "RC_B04R6_COURT_DEFECT_PACKAGE_PROMOTION_DRIFT", "package promotion remains deferred"),
        _pass_row("truth_engine_law_unchanged", "RC_B04R6_COURT_DEFECT_TRUTH_ENGINE_MUTATION", "truth-engine law is unchanged"),
        _pass_row("trust_zone_law_unchanged", "RC_B04R6_COURT_DEFECT_TRUST_ZONE_MUTATION", "trust-zone law is unchanged"),
        _pass_row("prep_only_source_packet_non_authority", "RC_B04R6_COURT_DEFECT_CANDIDATE_GENERATION_DRIFT", "AFSH source-packet drafts remain prep-only"),
        _pass_row("validation_plan_authored", "RC_B04R6_COURT_DEFECT_NEXT_MOVE_DRIFT", "court validation plan is emitted"),
        _pass_row("future_blocker_register_authored", "RC_B04R6_COURT_DEFECT_NEXT_MOVE_DRIFT", "future blockers are registered"),
    ]


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    current_branch: str,
    previous_validation_head: str,
    architecture_binding_head: str,
    status: str = "PASS",
) -> Dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "status": status,
        "generated_utc": generated_utc,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "previous_validation_head": previous_validation_head,
        "architecture_binding_head": architecture_binding_head,
        "selected_architecture_id": SELECTED_ARCHITECTURE_ID,
        "selected_architecture_name": SELECTED_ARCHITECTURE_NAME,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "current_branch": current_branch,
        "forbidden_claims": FORBIDDEN_CLAIMS,
        "r6_authorized": False,
        "r6_open": False,
        "router_generation_authorized": False,
        "candidate_generation_authorized": False,
        "candidate_training_authorized": False,
        "afsh_source_packet_authorized": False,
        "afsh_candidate_generation_authorized": False,
        "afsh_candidate_training_authorized": False,
        "shadow_screen_authorized": False,
        "shadow_screen_packet_authorized": False,
        "shadow_screen_execution_authorized": False,
        "learned_router_superiority_earned": False,
        "activation_review_authorized": False,
        "runtime_cutover_authorized": False,
        "learned_router_activated": False,
        "learned_router_cutover_authorized": False,
        "multi_lobe_authorized": False,
        "lobe_escalation_authorized": False,
        "package_promotion_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _verdict_modes() -> Dict[str, Dict[str, Any]]:
    return {
        "STATIC_HOLD": {
            "default": True,
            "positive_verdict": True,
            "description": "Use static comparator / no route when static hold is safest, sufficient, lower proof burden, or route value does not clear threshold.",
        },
        "ABSTAIN": {
            "default": False,
            "positive_verdict": True,
            "description": "Refuse routing when eligibility, trust zone, calibration, boundary status, context, or legal authority is uncertain.",
        },
        "NULL_ROUTE": {
            "default": False,
            "positive_verdict": True,
            "anti_overrouting_control": True,
            "description": "Anti-overrouting verdict when route pressure exists but no lawful route exists.",
        },
        "ROUTE_ELIGIBLE": {
            "default": False,
            "positive_verdict": False,
            "non_executing_precondition_only": True,
            "description": "A case may be considered by a later source-packet/candidate lane; this verdict does not authorize generation, screen execution, activation, or promotion.",
        },
    }


def _route_value_formula() -> Dict[str, Any]:
    return {
        "expression": " + ".join(ROUTE_VALUE_TERMS[:4]) + " - " + " - ".join(ROUTE_VALUE_TERMS[4:]),
        "terms": list(ROUTE_VALUE_TERMS),
        "route_eligible_requires": list(ROUTE_ELIGIBILITY_GATES),
    }


def _authorization_state() -> Dict[str, Any]:
    return {
        "r6_open": False,
        "learned_router_superiority": "UNEARNED",
        "candidate_generation_authorized": False,
        "candidate_training_authorized": False,
        "afsh_source_packet_authorized": False,
        "shadow_screen_packet_authorized": False,
        "shadow_screen_execution_authorized": False,
        "activation_cutover_authorized": False,
        "lobe_escalation_authorized": False,
        "package_promotion": "DEFERRED",
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
    }


def _validated_universe_binding(payloads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    receipt = payloads["validation_receipt"]
    return {
        "status": "BOUND_AND_VALIDATED",
        "validation_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "validation_receipt_head": receipt.get("current_git_head", ""),
        "case_namespace": "B04R6-AFSH-BU1-*",
        "case_count": EXPECTED_CASE_COUNT,
        "prior_r01_r04_treatment": "DIAGNOSTIC_ONLY",
        "prior_v2_six_row_treatment": "DIAGNOSTIC_ONLY",
    }


def _common_extra(payloads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "selected_outcome": SELECTED_OUTCOME,
        "allowed_outcomes": [OUTCOME_BOUND, OUTCOME_DEFERRED, OUTCOME_INVALID],
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "validated_blind_universe_binding": _validated_universe_binding(payloads),
        "verdict_modes": _verdict_modes(),
        "route_value_formula": _route_value_formula(),
        "route_eligible_cannot_authorize": [
            "AFSH source packet finalization",
            "AFSH candidate generation",
            "candidate training",
            "shadow-screen packet authorization",
            "shadow-screen execution",
            "learned-router superiority",
            "R6 opening",
            "activation review",
            "runtime cutover",
            "lobe escalation",
            "package promotion",
        ],
    }


def _artifact_payload(
    *,
    base: Dict[str, Any],
    schema_id: str,
    rows: list[Dict[str, str]],
    payloads: Dict[str, Dict[str, Any]],
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    failures = [row for row in rows if row.get("status") != "PASS"]
    payload = {
        "schema_id": schema_id,
        **base,
        **_common_extra(payloads),
        "validation_rows": rows,
        "failure_count": len(failures),
        "pass_count": len(rows) - len(failures),
    }
    if extra:
        payload.update(extra)
    return payload


def _static_hold_control() -> Dict[str, Any]:
    return {
        "default_verdict": True,
        "positive_success": True,
        "wins_when": [
            "static comparator is sufficient",
            "route value is below threshold",
            "proof burden increases without offsetting value",
            "case family is static-dominant",
            "mirror/masked siblings suggest instability",
            "input is outside route-eligible family",
            "route confidence is non-monotonic",
            "wrong-route cost exceeds expected gain",
        ],
        "reason_codes": REASON_CODES["STATIC_HOLD"],
    }


def _abstention_registry() -> Dict[str, Any]:
    return {
        "positive_success": True,
        "wins_when": [
            "input eligibility is uncertain",
            "trust-zone classification is uncertain",
            "boundary condition is active",
            "calibration is weak",
            "contradiction is unresolved by current law",
            "routing would depend on hidden labels or outcomes",
            "routing would require unavailable context",
            "screen execution would create unauthorized behavior",
        ],
        "reason_codes": REASON_CODES["ABSTAIN"],
    }


def _null_route_control() -> Dict[str, Any]:
    return {
        "anti_overrouting_control": True,
        "wins_when": [
            "route pressure exists but no lawful route exists",
            "selector would be tempted by surface features",
            "case is a null-route sibling",
            "route would be cosmetic movement",
            "trace shape could be satisfied without route value",
        ],
        "reason_codes": REASON_CODES["NULL_ROUTE"],
    }


def _route_economics_matrix() -> Dict[str, Any]:
    return {
        "formula": _route_value_formula(),
        "positive_terms": list(ROUTE_VALUE_TERMS[:4]),
        "penalty_terms": list(ROUTE_VALUE_TERMS[4:]),
        "eligibility_gates": list(ROUTE_ELIGIBILITY_GATES),
        "route_eligible_is_non_executing": True,
        "routing_requires_positive_permission": True,
        "metric_widening_allowed": False,
        "comparator_weakening_allowed": False,
    }


def _prep_only_authority_block() -> Dict[str, Any]:
    return {
        "status": "PREP_ONLY",
        "draft_status": "PREP_ONLY",
        "authority": "PREP_ONLY",
        "cannot_authorize_generation": True,
        "cannot_authorize_training": True,
        "cannot_authorize_screen_packet": True,
        "cannot_authorize_shadow_screen_execution": True,
        "cannot_authorize_activation": True,
        "cannot_authorize_package_promotion": True,
        "next_lawful_move_required_before_authority": NEXT_LAWFUL_MOVE,
        "allowed_future_purpose": "Draft scaffold only for AUTHOR_B04_R6_AFSH_IMPLEMENTATION_SOURCE_PACKET after court validation.",
    }


def _future_blocker_register() -> Dict[str, Any]:
    return {
        "schema_id": "kt.b04_r6.future_blocker_register.v1",
        "artifact_id": "B04_R6_FUTURE_BLOCKER_REGISTER",
        "current_authoritative_lane": "AUTHOR_B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT",
        "blockers": [
            {
                "blocker_id": "B04R6-FB-001",
                "future_blocker": "Court exists but court validation law does not exist.",
                "neutralization_now": [
                    OUTPUTS["validation_plan"],
                    OUTPUTS["validation_reason_codes"],
                    OUTPUTS["validation_test_plan"],
                ],
            },
            {
                "blocker_id": "B04R6-FB-002",
                "future_blocker": "Court validates but AFSH source-packet law does not exist.",
                "neutralization_now": [
                    OUTPUTS["afsh_source_packet_prep"],
                    OUTPUTS["afsh_features_prep"],
                    OUTPUTS["afsh_trace_prep"],
                    OUTPUTS["afsh_provenance_prep"],
                ],
            },
            {
                "blocker_id": "B04R6-FB-003",
                "future_blocker": "Source packet exists but source-packet validation law does not exist.",
                "neutralization_later": [
                    "b04_r6_afsh_source_packet_validation_plan.json",
                    "b04_r6_afsh_source_packet_validation_reason_codes.json",
                    "b04_r6_afsh_forbidden_feature_scanner_spec.json",
                ],
            },
            {
                "blocker_id": "B04R6-FB-004",
                "future_blocker": "Candidate exists but admissibility law is not ready.",
                "neutralization_later": [
                    "b04_r6_afsh_admissibility_court_contract_draft.json",
                    "b04_r6_afsh_admissibility_reason_codes_draft.json",
                    "b04_r6_afsh_trace_compatibility_validation_plan_draft.json",
                ],
            },
            {
                "blocker_id": "B04R6-FB-005",
                "future_blocker": "Candidate passes admissibility but shadow-screen packet law is missing.",
                "neutralization_later": [
                    "b04_r6_afsh_shadow_screen_execution_packet_draft.json",
                    "b04_r6_afsh_shadow_screen_metric_contract_draft.json",
                    "b04_r6_afsh_shadow_screen_disqualifier_ledger_draft.json",
                ],
            },
            {
                "blocker_id": "B04R6-FB-006",
                "future_blocker": "Shadow screen passes but activation review / rollback / runtime law is missing.",
                "neutralization_later": [
                    "b04_r6_learned_router_activation_review_packet_draft.json",
                    "b04_r6_learned_router_rollback_plan_draft.json",
                    "b04_r6_route_distribution_health_contract_draft.json",
                    "b04_r6_operator_override_contract_draft.json",
                    "b04_r6_kill_switch_contract_draft.json",
                ],
            },
            {
                "blocker_id": "B04R6-FB-007",
                "future_blocker": "Shadow screen fails but no lawful failure closeout or redesign path exists.",
                "neutralization_later": [
                    "b04_r6_superiority_not_earned_closeout_contract_draft.json",
                    "b04_r6_redesign_authorization_court_draft.json",
                    "b04_r6_forensic_invalidation_court_draft.json",
                ],
            },
            {
                "blocker_id": "B04R6-FB-008",
                "future_blocker": "External audit calls the proof self-referential.",
                "neutralization_later": [
                    "b04_r6_external_replay_requirements_draft.json",
                    "b04_r6_public_verifier_delta_packet_draft.json",
                    "monolith_vs_static_vs_afsh_matrix_draft.json",
                    "proof_bundle_comparison_draft.json",
                ],
            },
            {
                "blocker_id": "B04R6-FB-009",
                "future_blocker": "Commercial language outruns proof.",
                "neutralization_now": [
                    "r6_nonclaim_boundary_language_packet.json",
                    "learned_router_forbidden_claims_receipt.json",
                    "commercial_claim_ceiling_receipt.json",
                ],
            },
            {
                "blocker_id": "B04R6-FB-010",
                "future_blocker": "Lab/archive/generated surfaces contaminate canonical proof.",
                "neutralization_now": [
                    "r6_archive_diagnostic_only_receipt.json",
                    "r6_lab_to_canonical_promotion_guard.json",
                    "r6_generated_artifact_boundary_receipt.json",
                ],
            },
        ],
    }


def _report(rows: list[Dict[str, str]]) -> str:
    lines = [
        "# B04 R6 Static-Hold Abstention Route-Economics Court",
        "",
        f"Selected outcome: `{SELECTED_OUTCOME}`",
        "",
        "The court binds STATIC_HOLD as default, ABSTAIN as positive success, NULL_ROUTE as anti-overrouting control, and ROUTE_ELIGIBLE as a non-executing precondition only.",
        "",
        "No AFSH candidate generation, candidate training, shadow-screen execution, R6 opening, activation, lobe escalation, package promotion, or learned-router superiority is authorized.",
        "",
        f"Next lawful move: `{NEXT_LAWFUL_MOVE}`",
        "",
        "## Court Rows",
    ]
    for row in rows:
        lines.append(f"- `{row['check_id']}`: `{row['status']}` ({row['reason_code']})")
    lines.append("")
    return "\n".join(lines)


def run(*, reports_root: Path) -> Dict[str, Any]:
    root = repo_root()
    current_branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 route-economics court freeze")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    payloads = {role: _load(root, raw, label=role) for role, raw in INPUTS.items()}
    prep_payloads = {role: _load(root, raw, label=role) for role, raw in PREP_INPUTS.items()}
    _require_inputs(payloads, prep_payloads)

    fresh_trust_validation = validate_trust_zones(root=root)
    if fresh_trust_validation.get("status") != "PASS":
        raise RuntimeError("FAIL_CLOSED: fresh trust-zone validation must pass before court freeze")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main") if current_branch != "main" else head
    generated_utc = utc_now_iso_z()
    validation_rows = _validation_rows()
    previous_validation_head = str(payloads["validation_receipt"].get("current_git_head", "")).strip()
    architecture_binding_head = str(payloads["validation_receipt"].get("architecture_binding_head", "")).strip()
    base = _base(
        generated_utc=generated_utc,
        head=head,
        current_main_head=current_main_head,
        current_branch=current_branch,
        previous_validation_head=previous_validation_head,
        architecture_binding_head=architecture_binding_head,
    )

    static_hold = _static_hold_control()
    abstention = _abstention_registry()
    null_route = _null_route_control()
    route_economics = _route_economics_matrix()
    reason_taxonomy = {
        "schema_id": "kt.b04_r6.court_reason_code_taxonomy.v1",
        "artifact_id": "B04_R6_COURT_REASON_CODE_TAXONOMY",
        **base,
        "reason_codes": REASON_CODES,
    }
    disqualifiers = [
        "metric_widening",
        "comparator_weakening",
        "truth_engine_mutation",
        "trust_zone_mutation",
        "candidate_generation_authorization_drift",
        "shadow_screen_authorization_drift",
        "r6_open_drift",
        "activation_authorization_drift",
        "package_promotion_drift",
        "old_universe_reused_as_fresh_proof",
        "label_or_outcome_leakage",
        "route_eligibility_authorizes_execution",
    ]

    common_artifact_extra = {
        "authorization_state": _authorization_state(),
        "old_r01_r04_diagnostic_only": True,
        "old_v2_six_row_diagnostic_only": True,
        "metric_widening_allowed": False,
        "comparator_weakening_allowed": False,
        "input_bindings": _input_hashes(root),
    }

    outputs: Dict[str, Any] = {
        OUTPUTS["court_contract"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.static_hold_abstention_route_economics_court.v1",
            rows=validation_rows,
            payloads=payloads,
            extra={
                **common_artifact_extra,
                "artifact_id": "B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT",
                "court_scope": {
                    "purpose": "Define lawful static-hold, abstention, null-route, and route-eligibility economics before any AFSH source packet or candidate generation.",
                    "non_purpose": [
                        "Does not authorize AFSH candidate generation.",
                        "Does not authorize shadow-screen execution.",
                        "Does not open R6.",
                        "Does not earn learned-router superiority.",
                        "Does not authorize activation, lobe escalation, or package promotion.",
                    ],
                },
                "static_hold_law": static_hold,
                "abstention_law": abstention,
                "null_route_law": null_route,
                "route_eligible_law": {
                    "non_executing_precondition_only": True,
                    "wins_only_when": list(ROUTE_ELIGIBILITY_GATES),
                    "cannot_authorize": _common_extra(payloads)["route_eligible_cannot_authorize"],
                },
                "threshold_profile": {
                    "profile_id": "B04_R6_ROUTE_VALUE_THRESHOLD_PROFILE_V1",
                    "threshold_kind": "FROZEN_BEFORE_CANDIDATE_GENERATION",
                    "route_eligible_must_be_harder_than_static_hold": True,
                    "route_eligible_expected_to_be_rare": True,
                },
                "trust_zone_bindings": {
                    "must_pass_trust_zone_validation": True,
                    "fresh_trust_zone_validation": fresh_trust_validation,
                    "canonical_scope": "KT_PROD_CLEANROOM",
                    "lab_or_prep_only_artifacts": "NON_AUTHORITATIVE_UNLESS_PROMOTED_BY_NEXT_LAWFUL_MOVE",
                },
                "forbidden_actions": [
                    "AFSH_SOURCE_PACKET_AUTHORIZED",
                    "AFSH_CANDIDATE_GENERATION_AUTHORIZED",
                    "AFSH_CANDIDATE_TRAINING_AUTHORIZED",
                    "SHADOW_SCREEN_PACKET_AUTHORIZED",
                    "SHADOW_SCREEN_EXECUTION_AUTHORIZED",
                    "R6_OPEN",
                    "LEARNED_ROUTER_SUPERIORITY_EARNED",
                    "ACTIVATION_REVIEW_AUTHORIZED",
                    "RUNTIME_CUTOVER_AUTHORIZED",
                    "LOBE_ESCALATION_AUTHORIZED",
                    "PACKAGE_PROMOTION_AUTHORIZED",
                ],
            },
        ),
        OUTPUTS["court_receipt"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.static_hold_abstention_route_economics_court_receipt.v1",
            rows=validation_rows,
            payloads=payloads,
            extra={**common_artifact_extra, "verdict": SELECTED_OUTCOME},
        ),
        OUTPUTS["static_hold_control"]: {
            "schema_id": "kt.b04_r6.static_hold_control_contract.v1",
            **base,
            **_common_extra(payloads),
            **static_hold,
        },
        OUTPUTS["abstention_registry"]: {
            "schema_id": "kt.b04_r6.abstention_control_registry.v1",
            **base,
            **_common_extra(payloads),
            **abstention,
        },
        OUTPUTS["null_route_control"]: {
            "schema_id": "kt.b04_r6.null_route_control_contract.v1",
            **base,
            **_common_extra(payloads),
            **null_route,
        },
        OUTPUTS["route_economics"]: {
            "schema_id": "kt.b04_r6.route_economics_matrix.v1",
            **base,
            **_common_extra(payloads),
            **route_economics,
        },
        OUTPUTS["wrong_route_cost"]: {
            "schema_id": "kt.b04_r6.wrong_route_cost_contract.v1",
            **base,
            **_common_extra(payloads),
            "wrong_route_cost_required": True,
            "cost_components": [
                "quality_loss",
                "control_degradation",
                "abstention_violation",
                "overrouting_penalty",
                "proof_burden_increase",
                "trust_zone_risk",
            ],
        },
        OUTPUTS["wrong_static_hold_cost"]: {
            "schema_id": "kt.b04_r6.wrong_static_hold_cost_contract.v1",
            **base,
            **_common_extra(payloads),
            "wrong_static_hold_cost_required": True,
            "tracked_but_not_route_authorizing_by_itself": True,
            "cost_components": ["missed_route_value", "avoidable_proof_burden", "unclaimed_governance_benefit"],
        },
        OUTPUTS["proof_burden_delta"]: {
            "schema_id": "kt.b04_r6.proof_burden_delta_contract.v1",
            **base,
            **_common_extra(payloads),
            "proof_burden_delta_required": True,
            "routing_must_reduce_or_justify_proof_burden": True,
            "proof_burden_can_block_route": True,
        },
        OUTPUTS["threshold_profile"]: {
            "schema_id": "kt.b04_r6.route_value_threshold_profile.v1",
            **base,
            **_common_extra(payloads),
            "threshold_profile_id": "B04_R6_ROUTE_VALUE_THRESHOLD_PROFILE_V1",
            "threshold_kind": "FROZEN_BEFORE_CANDIDATE_GENERATION",
            "route_eligible_expected_to_be_rare": True,
            "route_threshold_mutation_requires_later_court": True,
        },
        OUTPUTS["reason_codes"]: reason_taxonomy,
        OUTPUTS["disqualifier_ledger"]: {
            "schema_id": "kt.b04_r6.court_disqualifier_ledger.v1",
            **base,
            **_common_extra(payloads),
            "terminal_disqualifiers": disqualifiers,
        },
        OUTPUTS["no_authorization_drift"]: _artifact_payload(
            base=base,
            schema_id="kt.b04_r6.court_no_authorization_drift_receipt.v1",
            rows=[row for row in validation_rows if row["check_id"].startswith("no_") or "forbidden" in row["check_id"]],
            payloads=payloads,
            extra={**common_artifact_extra, "no_downstream_authority_drift": True},
        ),
        OUTPUTS["validation_plan"]: {
            "schema_id": "kt.b04_r6.static_hold_abstention_route_economics_court_validation_plan.v1",
            **base,
            **_common_extra(payloads),
            "validation_checks": [row["check_id"] for row in validation_rows],
            "validator_next": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["validation_reason_codes"]: {
            "schema_id": "kt.b04_r6.static_hold_abstention_route_economics_court_validation_reason_codes.v1",
            **base,
            **_common_extra(payloads),
            "reason_codes": REASON_CODES,
        },
        OUTPUTS["afsh_source_packet_prep"]: {
            "schema_id": "kt.b04_r6.afsh_implementation_source_packet_prep_only_draft.v1",
            **base,
            **_common_extra(payloads),
            **_prep_only_authority_block(),
            "allowed_future_sections": [
                "allowed_features",
                "forbidden_features",
                "trace_schema",
                "provenance_matrix",
                "determinism_requirements",
                "no_network_rule",
                "no_runtime_mutation_rule",
                "no_truth_engine_mutation_rule",
                "no_trust_zone_mutation_rule",
                "no_package_promotion_rule",
                "candidate_generation_still_forbidden",
            ],
        },
        OUTPUTS["afsh_features_prep"]: {
            "schema_id": "kt.b04_r6.afsh_allowed_forbidden_features_prep_only_draft.v1",
            **base,
            **_common_extra(payloads),
            **_prep_only_authority_block(),
            "allowed_features": [
                "input_family_descriptors",
                "source_metadata_hashes",
                "static_comparator_features",
                "confidence_estimates",
                "calibration_bucket",
                "risk_bucket",
                "route_cost_estimate",
                "proof_burden_estimate",
                "trust_zone_eligibility_bit",
                "mirror_masked_stability_features",
            ],
            "forbidden_features": [
                "blind_outcome_labels",
                "blind_route_success_labels",
                "post_screen_labels",
                "hidden_adjudication_labels",
                "old_r01_r04_counted_labels",
                "old_v2_six_row_counted_labels",
                "package_promotion_flags",
                "activation_cutover_flags",
                "truth_engine_mutation_hooks",
                "trust_zone_mutation_hooks",
                "comparator_weakening_knobs",
                "metric_widening_knobs",
            ],
        },
        OUTPUTS["afsh_trace_prep"]: {
            "schema_id": "kt.b04_r6.afsh_trace_schema_prep_only_draft.v1",
            **base,
            **_common_extra(payloads),
            **_prep_only_authority_block(),
            "required_trace_groups": [
                "route_decision_trace",
                "abstention_trace",
                "null_route_trace",
                "overrouting_trace",
                "static_fallback_rationale",
                "mirror_masked_trace",
                "route_value_trace",
                "deterministic_replay_receipt",
            ],
        },
        OUTPUTS["afsh_provenance_prep"]: {
            "schema_id": "kt.b04_r6.afsh_provenance_matrix_prep_only_draft.v1",
            **base,
            **_common_extra(payloads),
            **_prep_only_authority_block(),
            "required_future_provenance": [
                "source_packet_hash",
                "allowed_feature_contract_hash",
                "forbidden_feature_contract_hash",
                "route_economics_contract_hash",
                "trace_schema_hash",
                "blind_universe_manifest_hash",
                "no_contamination_receipt",
            ],
        },
        OUTPUTS["future_blocker_register"]: {**base, **_common_extra(payloads), **_future_blocker_register()},
        OUTPUTS["next_lawful_move"]: {
            "schema_id": "kt.operator.b04_r6_next_lawful_move_receipt.v6",
            **base,
            **_common_extra(payloads),
            "verdict": SELECTED_OUTCOME,
        },
        OUTPUTS["court_report"]: _report(validation_rows),
        OUTPUTS["validation_test_plan"]: "# B04 R6 Static-Hold Abstention Route-Economics Court Validation Test Plan\n\n"
        "The next validator must prove the court preserves static hold as default, treats abstention and null-route as success controls, keeps route eligibility non-executing, and blocks every downstream authorization until a later source-packet lane.\n",
    }

    for filename, payload in outputs.items():
        path = reports_root / filename
        if isinstance(payload, str):
            path.write_text(payload, encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, payload)
    return {"verdict": SELECTED_OUTCOME, "next_lawful_move": NEXT_LAWFUL_MOVE, "pass_count": len(validation_rows)}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Author B04 R6 static-hold / abstention / route-economics court.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(reports_root=common.resolve_path(root, args.reports_root))
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
