from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-major-router-architecture-contract"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_MAJOR_ROUTER_ARCHITECTURE_CONTRACT"
PREVIOUS_LANE = "B04_R6_MAJOR_ROUTER_REDESIGN_SCOPE"

EXPECTED_PREVIOUS_OUTCOME = "R6_MAJOR_REDESIGN_SCOPE_AUTHORIZED__ARCHITECTURE_AND_BLIND_UNIVERSE_NEXT"
EXPECTED_PREVIOUS_NEXT_MOVE = "AUTHOR_B04_R6_MAJOR_ROUTER_ARCHITECTURE_CONTRACT"

OUTCOME_BOUND = "R6_MAJOR_ROUTER_ARCHITECTURE_CONTRACT_BOUND__BLIND_UNIVERSE_CONTRACT_NEXT"
OUTCOME_DEFERRED = "R6_DEFERRED__ARCHITECTURE_CONTRACT_DEFECT_REMAINS"
OUTCOME_CLOSEOUT = "R6_CLOSEOUT__NO_LAWFUL_REDESIGN_ARCHITECTURE_SELECTED"
SELECTED_OUTCOME = OUTCOME_BOUND
NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_NEW_BLIND_INPUT_UNIVERSE_CONTRACT"

SELECTED_ARCHITECTURE_ID = "AFSH-2S-GUARD"
SELECTED_ARCHITECTURE_NAME = "Abstention-First Static-Hold Two-Stage Guarded Router"

FORBIDDEN_CLAIMS = [
    "r6_open",
    "learned_router_superiority_earned",
    "activation_review_authorized",
    "learned_router_activated",
    "learned_router_cutover_authorized",
    "multi_lobe_authorized",
    "package_promotion_approved",
    "commercial_broadening",
]

INPUTS = {
    "v1_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_superiority_screen_receipt.json",
    "v2_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_second_shadow_screen_result_receipt.json",
    "forensic_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_second_shadow_screen_forensic_receipt.json",
    "rerun_bar_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_second_shadow_screen_rerun_bar_receipt.json",
    "guard_failure_matrix": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v2_guard_failure_matrix.json",
    "prior_scope_packet": "KT_PROD_CLEANROOM/reports/b04_r6_major_router_redesign_scope_packet.json",
    "prior_scope_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_major_router_redesign_scope_receipt.json",
    "prior_retirement_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_family_retirement_receipt.json",
    "prior_redesign_blocker_ledger": "KT_PROD_CLEANROOM/reports/b04_r6_major_redesign_blocker_ledger.json",
    "prior_architecture_options": "KT_PROD_CLEANROOM/reports/b04_r6_major_router_architecture_options_matrix.json",
}

HANDOFF_INPUTS = {
    "previous_next_lawful_move": "KT_PROD_CLEANROOM/reports/b04_r6_next_lawful_move_receipt.json",
}

OUTPUTS = {
    "architecture_contract": "b04_r6_major_router_architecture_contract.json",
    "architecture_receipt": "b04_r6_major_router_architecture_contract_receipt.json",
    "router_family_retirement": "b04_r6_router_family_retirement_receipt.json",
    "architecture_options": "b04_r6_architecture_options_matrix.json",
    "architecture_selection_rationale": "b04_r6_architecture_selection_rationale.json",
    "v1_v2_failure_synthesis": "b04_r6_v1_v2_failure_synthesis.json",
    "candidate_family_autopsy": "b04_r6_candidate_family_autopsy.json",
    "abstention_first_draft": "b04_r6_abstention_first_router_contract_draft.json",
    "overrouting_containment_draft": "b04_r6_overrouting_containment_contract_draft.json",
    "control_preservation_draft": "b04_r6_control_preservation_contract_draft.json",
    "uncertainty_calibration_draft": "b04_r6_uncertainty_calibration_gate_contract_draft.json",
    "confidence_monotonicity_draft": "b04_r6_confidence_to_error_monotonicity_receipt_draft.json",
    "new_blind_selection_risk": "b04_r6_new_blind_universe_selection_risk_matrix.json",
    "static_dominance": "b04_r6_static_comparator_dominance_analysis.json",
    "research_translation": "b04_r6_routing_research_translation_matrix.json",
    "architecture_clean_state": "b04_r6_architecture_clean_state_watchdog_receipt.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
    "report_md": "COHORT0_B04_R6_MAJOR_ROUTER_ARCHITECTURE_CONTRACT_REPORT.md",
}


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


def _ensure_false_if_present(payload: Dict[str, Any], key: str, *, label: str) -> None:
    if key in payload and payload.get(key) is not False:
        raise RuntimeError(f"FAIL_CLOSED: {label} must keep {key}=false")


def _ensure_boundaries(payload: Dict[str, Any], *, label: str) -> None:
    status = str(payload.get("status", "")).strip()
    if status not in {"PASS", "FROZEN_PACKET", "PREP_ONLY"}:
        raise RuntimeError(f"FAIL_CLOSED: {label} must have PASS/FROZEN_PACKET/PREP_ONLY status")
    for key in (
        "r6_authorized",
        "r6_open",
        "learned_router_superiority_earned",
        "activation_review_authorized",
        "learned_router_activated",
        "learned_router_cutover_authorized",
        "multi_lobe_authorized",
    ):
        _ensure_false_if_present(payload, key, label=label)
    if payload.get("package_promotion_remains_deferred") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve package promotion deferral")
    if payload.get("truth_engine_derivation_law_unchanged") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve truth-engine law")
    if payload.get("trust_zone_law_unchanged") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve trust-zone law")


def _base(*, generated_utc: str, head: str, status: str = "PASS") -> Dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "status": status,
        "generated_utc": generated_utc,
        "current_git_head": head,
        "subject_main_head": head,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "forbidden_claims": FORBIDDEN_CLAIMS,
        "r6_authorized": False,
        "r6_open": False,
        "learned_router_superiority_earned": False,
        "activation_review_authorized": False,
        "learned_router_activated": False,
        "learned_router_cutover_authorized": False,
        "multi_lobe_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _input_hashes(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in sorted(INPUTS.items()):
        path = root / raw
        if not path.is_file():
            raise RuntimeError(f"FAIL_CLOSED: missing required input: {raw}")
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    return rows


def _rows(payload: Dict[str, Any], *, label: str) -> list[Dict[str, Any]]:
    rows = payload.get("rows", payload.get("entries", payload.get("options", [])))
    if not isinstance(rows, list):
        raise RuntimeError(f"FAIL_CLOSED: {label} missing rows/entries/options list")
    return [dict(row) for row in rows if isinstance(row, dict)]


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


def _require_inputs(
    payloads: Dict[str, Dict[str, Any]], *, handoff_payloads: Dict[str, Dict[str, Any]], current_branch: str
) -> None:
    for label, payload in payloads.items():
        _ensure_boundaries(payload, label=label)
    for label, payload in handoff_payloads.items():
        _ensure_boundaries(payload, label=label)

    if int(payloads["v1_receipt"].get("candidate_win_count", -1)) != 0:
        raise RuntimeError("FAIL_CLOSED: v1 must have zero candidate wins")
    if int(payloads["v1_receipt"].get("case_count", -1)) != 4:
        raise RuntimeError("FAIL_CLOSED: v1 must be the four-row first screen")
    if int(payloads["v1_receipt"].get("disqualifier_count", -1)) != 0:
        raise RuntimeError("FAIL_CLOSED: v1 guard law must be preserved")

    if int(payloads["v2_receipt"].get("candidate_win_count", -1)) != 0:
        raise RuntimeError("FAIL_CLOSED: v2 must have zero candidate wins")
    if int(payloads["v2_receipt"].get("case_count", -1)) != 6:
        raise RuntimeError("FAIL_CLOSED: v2 must be the six-row blind screen")
    if int(payloads["v2_receipt"].get("disqualifier_count", -1)) != 3:
        raise RuntimeError("FAIL_CLOSED: v2 must carry three hard disqualifiers")

    forensic = payloads["forensic_receipt"]
    if forensic.get("cause_class") != "CANDIDATE_BEHAVIOR_DEFECT":
        raise RuntimeError("FAIL_CLOSED: architecture contract requires candidate-behavior forensic cause")
    if forensic.get("candidate_v2_disqualified_for_current_r6_screen_law") is not True:
        raise RuntimeError("FAIL_CLOSED: candidate v2 must be disqualified")

    rerun_bar = payloads["rerun_bar_receipt"]
    if rerun_bar.get("rerun_allowed") is not False or rerun_bar.get("rerun_bar_active") is not True:
        raise RuntimeError("FAIL_CLOSED: second shadow rerun must be barred")

    scope = payloads["prior_scope_receipt"]
    if scope.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: previous scope court did not authorize architecture contract")
    if scope.get("architecture_contract_next") is not True:
        raise RuntimeError("FAIL_CLOSED: previous scope court must name architecture contract next")
    if scope.get("candidate_generation_authorized") is not False:
        raise RuntimeError("FAIL_CLOSED: candidate generation must remain unauthorized")
    if scope.get("new_shadow_screen_authorized") is not False:
        raise RuntimeError("FAIL_CLOSED: new shadow screen must remain unauthorized")
    if scope.get("quick_candidate_v3_forbidden") is not True:
        raise RuntimeError("FAIL_CLOSED: quick candidate v3 must be forbidden")

    retirement = payloads["prior_retirement_receipt"]
    if retirement.get("retired_for_r6") is not True:
        raise RuntimeError("FAIL_CLOSED: v1/v2 router family must be retired for R6")
    if retirement.get("quick_candidate_v3_forbidden") is not True:
        raise RuntimeError("FAIL_CLOSED: retirement receipt must forbid quick v3")
    if retirement.get("old_blind_universes_diagnostic_only") is not True:
        raise RuntimeError("FAIL_CLOSED: old blind universes must be diagnostic-only")

    options = _rows(payloads["prior_architecture_options"], label="prior architecture options")
    if not any(row.get("option_id") == "ABSTENTION_FIRST_STATIC_HOLD_ROUTER" for row in options):
        raise RuntimeError("FAIL_CLOSED: abstention-first static-hold option must be present")

    acceptable_next_moves = {EXPECTED_PREVIOUS_NEXT_MOVE}
    if current_branch == "main":
        acceptable_next_moves.add(NEXT_LAWFUL_MOVE)
    if handoff_payloads["previous_next_lawful_move"].get("next_lawful_move") not in acceptable_next_moves:
        raise RuntimeError("FAIL_CLOSED: previous next-lawful-move receipt mismatch")

    guard_rows = _rows(payloads["guard_failure_matrix"], label="guard failure matrix")
    if not any(row.get("control_degradation") is True for row in guard_rows):
        raise RuntimeError("FAIL_CLOSED: missing control-degradation guard evidence")
    if not any(row.get("abstention_collapse") is True for row in guard_rows):
        raise RuntimeError("FAIL_CLOSED: missing abstention-collapse guard evidence")
    if not any(row.get("overrouting_collapse") is True for row in guard_rows):
        raise RuntimeError("FAIL_CLOSED: missing over-routing-collapse guard evidence")


def _retirement_record() -> Dict[str, Any]:
    return {
        "retired_family_id": "minimal_deterministic_shadow_router_family_v1_v2",
        "retired_for_r6": True,
        "quick_candidate_v3_forbidden": True,
        "v1_result": {"candidate_wins": 0, "case_count": 4, "disqualifiers": 0, "guards_preserved": True},
        "v2_result": {
            "candidate_wins": 0,
            "case_count": 6,
            "disqualifiers": [
                "CONTROL_DEGRADATION",
                "ABSTENTION_COLLAPSE",
                "OVERRouting_COLLAPSE",
            ],
            "forensic_cause": "CANDIDATE_BEHAVIOR_DEFECT",
            "rerun_bar_active": True,
        },
        "old_screen_evidence_policy": {
            "r01_r04_diagnostic_only": True,
            "six_row_second_screen_diagnostic_only": True,
            "reuse_as_fresh_counted_proof_allowed": False,
        },
    }


def _major_redesign_definition() -> Dict[str, Any]:
    return {
        "material_architecture_change_required": True,
        "weight_or_threshold_only_patch_counts": False,
        "selected_architecture_id": SELECTED_ARCHITECTURE_ID,
        "selected_architecture_name": SELECTED_ARCHITECTURE_NAME,
        "required_structural_features": [
            "static_hold_default",
            "explicit_abstention_gate",
            "uncertainty_or_calibration_gate",
            "risk_aware_selector",
            "guard_ensemble_before_route_admission",
            "deterministic_trace_and_replay_law",
        ],
        "forbidden_non_redesigns": [
            "quick_candidate_v3_patch",
            "pure_learned_selector_without_static_hold_default",
            "threshold_only_tuning",
            "metric_widening",
            "static_baseline_weakening",
            "disqualifier_softening",
        ],
    }


def _selected_architecture_contract() -> Dict[str, Any]:
    return {
        "architecture_id": SELECTED_ARCHITECTURE_ID,
        "architecture_name": SELECTED_ARCHITECTURE_NAME,
        "default_outcome": "STATIC_HOLD",
        "route_requires_positive_justification": True,
        "abstention_requires_extra_justification": False,
        "stage_0_authority_and_input_eligibility_gate": {
            "purpose": "Reject execution before routing if authority, input, or boundary preconditions fail.",
            "fail_action": "STATIC_HOLD_OR_BLOCK",
            "required_checks": [
                "canonical_input_manifest_valid",
                "new_blind_universe_valid",
                "candidate_source_admissible",
                "comparator_contract_unchanged",
                "metric_contract_unchanged",
                "trust_zone_validation_pass",
                "no_package_promotion_dependency",
                "no_truth_engine_or_trust_zone_mutation_dependency",
            ],
        },
        "stage_1_abstention_uncertainty_gate": {
            "purpose": "Decide whether learned routing is even eligible.",
            "default_action": "STATIC_HOLD",
            "route_only_if_all_pass": [
                "routing_eligibility_true",
                "uncertainty_below_contract_threshold",
                "confidence_calibrated",
                "mirror_masked_behavior_stable",
                "expected_route_value_exceeds_static_hold_margin",
                "abstention_not_safer_than_route",
            ],
        },
        "stage_2_risk_aware_selector": {
            "purpose": "Select a learned route only after Stage 1 admits routing.",
            "required_trace_fields": [
                "selected_route",
                "static_fallback_alternative",
                "route_confidence",
                "expected_route_margin",
                "overrouting_risk",
                "abstention_reason_if_held",
                "comparator_safe_trace",
            ],
        },
        "stage_3_guard_ensemble": {
            "purpose": "Reject or convert route to static-hold before any counted decision if guard law fails.",
            "guards": [
                "control_preservation",
                "abstention_preservation",
                "overrouting_containment",
                "no_regression_against_static_baseline",
                "mirror_masked_invariance",
                "route_distribution_health",
                "trace_completeness",
            ],
            "guard_failure_action": "ROUTE_INADMISSIBLE_OR_STATIC_HOLD",
        },
        "stage_4_receipt_and_replay": {
            "required_outputs": [
                "route_decision_trace",
                "abstention_trace",
                "overrouting_trace",
                "static_fallback_rationale",
                "mirror_masked_trace",
                "deterministic_replay_receipt",
            ],
        },
    }


def _new_blind_universe_requirement() -> Dict[str, Any]:
    return {
        "new_blind_universe_required_before_source_packet": True,
        "old_screen_evidence_diagnostic_only": True,
        "r01_r04_reuse_as_counted_proof_allowed": False,
        "six_row_second_screen_reuse_as_fresh_counted_proof_allowed": False,
        "required_future_receipts": [
            "new_case_id_manifest",
            "source_hash_manifest",
            "family_coverage_matrix",
            "mirror_masked_sibling_policy",
            "holdout_separation_receipt",
            "leakage_guard_receipt",
        ],
    }


def _comparator_metric_preservation() -> Dict[str, Any]:
    return {
        "existing_comparator_law_preserved": True,
        "existing_metric_thresholds_preserved": True,
        "static_baseline_weakening_allowed": False,
        "metric_widening_allowed": False,
        "disqualifier_softening_allowed": False,
        "contract_change_requires_separate_authoritative_court": True,
    }


def _architecture_options() -> list[Dict[str, Any]]:
    return [
        {
            "option_id": "ABSTENTION_FIRST_STATIC_HOLD_TWO_STAGE_GUARDED_ROUTER",
            "formal_id": SELECTED_ARCHITECTURE_ID,
            "selected": True,
            "addresses": ["CONTROL_DEGRADATION", "ABSTENTION_COLLAPSE", "OVERRouting_COLLAPSE"],
            "default_action": "STATIC_HOLD",
            "risk": "LOWEST_AMONG_REDESIGN_OPTIONS_FOR_OBSERVED_FAILURES",
        },
        {
            "option_id": "CONFORMAL_UNCERTAINTY_GATED_ROUTER",
            "selected": False,
            "addresses": ["ABSTENTION_COLLAPSE", "CONTROL_DEGRADATION"],
            "reason_not_selected_first": "Useful as Stage 1 calibration strategy, but less complete than full AFSH two-stage guard.",
        },
        {
            "option_id": "TWO_STAGE_PERFORMANCE_PREDICTOR_SELECTOR",
            "selected": False,
            "addresses": ["STATIC_COMPARATOR_DOMINANCE", "CONTROL_DEGRADATION"],
            "reason_not_selected_first": "Useful as Stage 2 selector substrate, but needs abstention-first default wrapped around it.",
        },
        {
            "option_id": "COST_AWARE_SELECTOR_WITH_STATIC_FALLBACK",
            "selected": False,
            "addresses": ["OVERRouting_COLLAPSE", "CONTROL_DEGRADATION"],
            "reason_not_selected_first": "Cost/risk awareness is useful, but insufficient alone against abstention collapse.",
        },
        {
            "option_id": "PURE_LEARNED_SELECTOR",
            "selected": False,
            "rejected": True,
            "rejection_reason": "High risk after v2 over-routing and abstention collapse; no static-hold default.",
        },
    ]


def _selection_rationale() -> Dict[str, Any]:
    return {
        "selected_architecture_id": SELECTED_ARCHITECTURE_ID,
        "selected_architecture_name": SELECTED_ARCHITECTURE_NAME,
        "primary_reason": "The new architecture makes routing rare, justified, traceable, and reversible.",
        "maps_to_v2_failures": [
            {
                "v2_failure": "CONTROL_DEGRADATION",
                "architecture_response": "Stage 3 guard ensemble plus static fallback before route admission.",
            },
            {
                "v2_failure": "ABSTENTION_COLLAPSE",
                "architecture_response": "Stage 1 abstention/uncertainty gate with static-hold default.",
            },
            {
                "v2_failure": "OVERRouting_COLLAPSE",
                "architecture_response": "Over-routing risk trace, route-rate containment, and static-hold fallback.",
            },
        ],
        "why_not_quick_v3": "A quick v3 would patch a retired unsafe family instead of changing routing law.",
        "why_not_pure_learned_selector": "It increases the same eager-routing risk that invalidated candidate v2.",
    }


def _failure_synthesis() -> Dict[str, Any]:
    return {
        "v1_failure_class": "CAPABILITY_FAILURE_WITH_GUARDS_PRESERVED",
        "v2_failure_class": "INVALIDATED_CANDIDATE_BEHAVIOR_DEFECT",
        "aggregate_candidate_wins": 0,
        "aggregate_counted_cases": 10,
        "hard_disqualifiers_observed": [
            "CONTROL_DEGRADATION",
            "ABSTENTION_COLLAPSE",
            "OVERRouting_COLLAPSE",
        ],
        "current_candidate_family_status": "RETIRED_FOR_R6",
        "architecture_implication": "New router family must be abstention-first with static-hold default and guard-before-route law.",
    }


def _abstention_first_draft() -> Dict[str, Any]:
    return {
        "draft_status": "PREP_ONLY",
        "default_decision": "STATIC_HOLD",
        "routing_is_exception": True,
        "required_gate_inputs": [
            "eligibility_signal",
            "uncertainty_score",
            "calibration_status",
            "mirror_masked_stability_status",
            "route_margin_over_static",
        ],
        "fail_actions": {
            "missing_signal": "STATIC_HOLD",
            "uncertainty_high": "STATIC_HOLD",
            "calibration_fail": "STATIC_HOLD",
            "mirror_masked_instability": "STATIC_HOLD",
        },
    }


def _overrouting_draft() -> Dict[str, Any]:
    return {
        "draft_status": "PREP_ONLY",
        "route_rate_ceiling_required": True,
        "static_hold_floor_required": True,
        "overrouting_risk_trace_required": True,
        "overrouting_collapse_disqualifier_preserved": True,
        "metric_widening_allowed": False,
    }


def _control_preservation_draft() -> Dict[str, Any]:
    return {
        "draft_status": "PREP_ONLY",
        "static_baseline_control_preserved": True,
        "no_regression_guard_required": True,
        "guard_failure_default_action": "STATIC_HOLD_OR_INVALIDATE",
        "control_degradation_disqualifier_preserved": True,
    }


def _calibration_draft() -> Dict[str, Any]:
    return {
        "draft_status": "PREP_ONLY",
        "uncertainty_gate_required": True,
        "confidence_calibration_required": True,
        "static_hold_on_uncertainty": True,
        "confidence_to_error_monotonicity_required": True,
        "calibration_failure_action": "STATIC_HOLD",
    }


def _blind_risk_matrix() -> list[Dict[str, Any]]:
    return [
        {
            "risk_id": "OLD_SCREEN_LABEL_LEAKAGE",
            "applies_to": ["R01_R04", "SECOND_SIX_ROW_SCREEN"],
            "mitigation": "Old screens diagnostic-only; no counted proof reuse.",
            "blocking_if_detected": True,
        },
        {
            "risk_id": "MUTATED_SIBLING_OVERFITTING",
            "applies_to": ["new_blind_universe_candidate_set"],
            "mitigation": "Bind source hashes and family coverage before candidate source generation.",
            "blocking_if_detected": True,
        },
        {
            "risk_id": "MIRROR_MASKED_SURFACE_ARTIFACT",
            "applies_to": ["new_blind_universe_candidate_set"],
            "mitigation": "Require mirror/masked sibling policy and invariance receipt.",
            "blocking_if_detected": True,
        },
    ]


def _research_translation() -> list[Dict[str, Any]]:
    return [
        {
            "research_family": "RouteLLM-style cost-quality routing",
            "kt_translation": "cost/risk-aware selector only after abstention gate; no research result is proof",
            "required_receipts_before_authority": ["cost_contract", "quality_margin_trace", "static_fallback_receipt"],
        },
        {
            "research_family": "predictor-plus-selector routing",
            "kt_translation": "Stage 2 selector candidate, wrapped by Stage 1 static-hold default",
            "required_receipts_before_authority": ["predictor_provenance", "selector_trace_schema", "holdout_separation"],
        },
        {
            "research_family": "calibration/conformal abstention",
            "kt_translation": "uncertainty gate and static-hold-on-uncertainty law",
            "required_receipts_before_authority": ["calibration_receipt", "coverage_guard", "monotonicity_check"],
        },
        {
            "research_family": "shadow rollout discipline",
            "kt_translation": "shadow-only execution packet before any activation review",
            "required_receipts_before_authority": ["shadow_packet", "disqualifier_ledger", "no_regression_matrix"],
        },
    ]


def _report(selected_outcome: str, next_move: str) -> str:
    return (
        "# Cohort-0 B04 R6 Major Router Architecture Contract\n\n"
        f"Selected outcome: `{selected_outcome}`\n\n"
        f"Selected architecture: `{SELECTED_ARCHITECTURE_ID}` "
        f"({SELECTED_ARCHITECTURE_NAME}).\n\n"
        "This architecture is abstention-first, static-hold default, and guarded before any route can become "
        "admissible. It is selected specifically because v2 failed through control degradation, abstention "
        "collapse, and over-routing collapse.\n\n"
        "This packet does not authorize candidate generation, a new shadow screen, R6 opening, learned-router "
        "activation, lobe escalation, package promotion, metric widening, comparator weakening, or old blind "
        "universe reuse as fresh proof.\n\n"
        f"Next lawful move: `{next_move}`\n"
    )


def run(*, reports_root: Path) -> Dict[str, Any]:
    root = repo_root()
    current_branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 major-router-architecture contract freeze")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    payloads = {role: _load(root, raw, label=role) for role, raw in INPUTS.items()}
    handoff_payloads = {role: _load(root, raw, label=role) for role, raw in HANDOFF_INPUTS.items()}
    _require_inputs(payloads, handoff_payloads=handoff_payloads, current_branch=current_branch)

    trust_validation = validate_trust_zones(root=root)
    common.ensure_pass(trust_validation, label="trust-zone validation")
    if trust_validation.get("failures"):
        raise RuntimeError("FAIL_CLOSED: trust-zone validation must have zero failures")

    generated_utc = utc_now_iso_z()
    head = common.git_rev_parse(root, "HEAD")
    base = _base(generated_utc=generated_utc, head=head)
    input_bindings = _input_hashes(root)
    retirement = _retirement_record()
    redesign_definition = _major_redesign_definition()
    architecture_contract = _selected_architecture_contract()
    blind_law = _new_blind_universe_requirement()
    comparator_law = _comparator_metric_preservation()
    options = _architecture_options()
    rationale = _selection_rationale()
    failure_synthesis = _failure_synthesis()

    common_decision = {
        "selected_outcome": SELECTED_OUTCOME,
        "allowed_outcomes": [OUTCOME_BOUND, OUTCOME_DEFERRED, OUTCOME_CLOSEOUT],
        "selected_architecture_id": SELECTED_ARCHITECTURE_ID,
        "selected_architecture_name": SELECTED_ARCHITECTURE_NAME,
        "architecture_contract_bound": True,
        "candidate_family_retired_for_r6": True,
        "quick_candidate_v3_forbidden": True,
        "candidate_generation_authorized": False,
        "new_shadow_screen_authorized": False,
        "new_blind_universe_required": True,
        "old_blind_universes_diagnostic_only": True,
        "comparator_metric_preservation_required": True,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }

    outputs: Dict[str, Any] = {
        OUTPUTS["architecture_contract"]: {
            "schema_id": "kt.operator.b04_r6_major_router_architecture_contract.v1",
            **base,
            **common_decision,
            "court_question": "Which major router architecture is lawfully selected before blind-universe binding?",
            "input_bindings": input_bindings,
            "v1_v2_retirement_record": retirement,
            "major_redesign_definition": redesign_definition,
            "selected_architecture_contract": architecture_contract,
            "new_blind_universe_requirement": blind_law,
            "comparator_metric_preservation_law": comparator_law,
        },
        OUTPUTS["architecture_receipt"]: {
            "schema_id": "kt.operator.b04_r6_major_router_architecture_contract_receipt.v1",
            **base,
            **common_decision,
            "status": "PASS",
            "verdict": SELECTED_OUTCOME,
        },
        OUTPUTS["router_family_retirement"]: {
            "schema_id": "kt.operator.b04_r6_router_family_retirement_receipt.v1",
            **base,
            **retirement,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["architecture_options"]: {
            "schema_id": "kt.operator.b04_r6_architecture_options_matrix.v1",
            **base,
            "options": options,
            "selected_architecture_id": SELECTED_ARCHITECTURE_ID,
            "candidate_generation_authorized": False,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["architecture_selection_rationale"]: {
            "schema_id": "kt.operator.b04_r6_architecture_selection_rationale.v1",
            **base,
            **rationale,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["v1_v2_failure_synthesis"]: {
            "schema_id": "kt.operator.b04_r6_v1_v2_failure_synthesis.v1",
            **base,
            **failure_synthesis,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["candidate_family_autopsy"]: {
            "schema_id": "kt.operator.b04_r6_candidate_family_autopsy.v2",
            **base,
            **failure_synthesis,
            "candidate_family_retired_for_r6": True,
            "quick_candidate_v3_forbidden": True,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["abstention_first_draft"]: {
            "schema_id": "kt.operator.b04_r6_abstention_first_router_contract_draft.v2",
            **base,
            "status": "PREP_ONLY",
            **_abstention_first_draft(),
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["overrouting_containment_draft"]: {
            "schema_id": "kt.operator.b04_r6_overrouting_containment_contract_draft.v2",
            **base,
            "status": "PREP_ONLY",
            **_overrouting_draft(),
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["control_preservation_draft"]: {
            "schema_id": "kt.operator.b04_r6_control_preservation_contract_draft.v1",
            **base,
            "status": "PREP_ONLY",
            **_control_preservation_draft(),
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["uncertainty_calibration_draft"]: {
            "schema_id": "kt.operator.b04_r6_uncertainty_calibration_gate_contract_draft.v1",
            **base,
            "status": "PREP_ONLY",
            **_calibration_draft(),
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["confidence_monotonicity_draft"]: {
            "schema_id": "kt.operator.b04_r6_confidence_to_error_monotonicity_receipt_draft.v1",
            **base,
            "status": "PREP_ONLY",
            "monotonicity_required": True,
            "confidence_increase_must_not_increase_error_risk_without_flag": True,
            "candidate_generation_authorized": False,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["new_blind_selection_risk"]: {
            "schema_id": "kt.operator.b04_r6_new_blind_universe_selection_risk_matrix.v1",
            **base,
            "status": "PREP_ONLY",
            "risks": _blind_risk_matrix(),
            "blind_universe_binding_authorized_by_this_packet": False,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["static_dominance"]: {
            "schema_id": "kt.operator.b04_r6_static_comparator_dominance_analysis.v4",
            **base,
            "status": "PREP_ONLY",
            "static_baseline_remains_control": True,
            "candidate_family_never_beat_static": True,
            "aggregate_candidate_wins": 0,
            "aggregate_counted_cases": 10,
            "static_baseline_weakening_allowed": False,
            "metric_widening_allowed": False,
            "architecture_response": "Route only when AFSH gate proves expected margin over static hold.",
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["research_translation"]: {
            "schema_id": "kt.operator.b04_r6_routing_research_translation_matrix.v1",
            **base,
            "status": "PREP_ONLY",
            "research_is_advisory_not_proof": True,
            "translations": _research_translation(),
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["architecture_clean_state"]: {
            "schema_id": "kt.operator.b04_r6_architecture_clean_state_watchdog_receipt.v1",
            **base,
            "status": "PASS",
            "candidate_generation_detected": False,
            "old_blind_universe_reuse_detected": False,
            "metric_widening_detected": False,
            "comparator_weakening_detected": False,
            "package_promotion_drift": False,
            "truth_engine_mutation_detected": False,
            "trust_zone_mutation_detected": False,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["next_lawful_move"]: {
            "schema_id": "kt.operator.b04_r6_next_lawful_move_receipt.v3",
            **base,
            **common_decision,
            "verdict": SELECTED_OUTCOME,
        },
        OUTPUTS["report_md"]: _report(SELECTED_OUTCOME, NEXT_LAWFUL_MOVE),
    }

    for filename, payload in outputs.items():
        path = reports_root / filename
        if isinstance(payload, str):
            path.write_text(payload, encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, payload)
    return {"verdict": SELECTED_OUTCOME, "next_lawful_move": NEXT_LAWFUL_MOVE}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Freeze B04 R6 major router architecture contract.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(reports_root=common.resolve_path(root, args.reports_root))
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
