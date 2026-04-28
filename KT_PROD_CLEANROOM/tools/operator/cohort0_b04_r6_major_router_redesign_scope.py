from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-major-router-redesign-scope"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_MAJOR_ROUTER_REDESIGN_SCOPE"
PREVIOUS_LANE = "B04_R6_CANDIDATE_V2_DISQUALIFICATION_AND_CLOSEOUT_OR_MAJOR_REDESIGN"

EXPECTED_PREVIOUS_OUTCOME = "R6_MAJOR_REDESIGN_AUTHORIZED__NEW_ROUTER_ARCHITECTURE_AND_NEW_BLIND_UNIVERSE_REQUIRED"
EXPECTED_PREVIOUS_NEXT_MOVE = (
    "AUTHOR_B04_R6_MAJOR_ROUTER_REDESIGN_SCOPE_PACKET__NEW_ARCHITECTURE_AND_NEW_BLIND_UNIVERSE_REQUIRED"
)

OUTCOME_SCOPE_AUTHORIZED = "R6_MAJOR_REDESIGN_SCOPE_AUTHORIZED__ARCHITECTURE_AND_BLIND_UNIVERSE_NEXT"
OUTCOME_DEFERRED = "R6_DEFERRED__REDESIGN_SCOPE_INSUFFICIENT"
OUTCOME_CLOSEOUT = "R6_CLOSEOUT__NO_LAWFUL_MAJOR_REDESIGN_PATH_ON_CURRENT_SUBSTRATE"
SELECTED_OUTCOME = OUTCOME_SCOPE_AUTHORIZED
NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_MAJOR_ROUTER_ARCHITECTURE_CONTRACT"

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
    "prior_disqualification_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v2_disqualification_receipt.json",
    "prior_family_autopsy": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_family_autopsy.json",
    "prior_major_redesign_options": "KT_PROD_CLEANROOM/reports/b04_r6_major_redesign_options_matrix.json",
    "prior_redesign_blocker_ledger": "KT_PROD_CLEANROOM/reports/b04_r6_closeout_or_major_redesign_blocker_ledger.json",
}

HANDOFF_INPUTS = {
    "previous_next_lawful_move": "KT_PROD_CLEANROOM/reports/b04_r6_next_lawful_move_receipt.json",
}

OUTPUTS = {
    "scope_packet": "b04_r6_major_router_redesign_scope_packet.json",
    "scope_receipt": "b04_r6_major_router_redesign_scope_receipt.json",
    "candidate_family_retirement": "b04_r6_candidate_family_retirement_receipt.json",
    "major_redesign_blocker_ledger": "b04_r6_major_redesign_blocker_ledger.json",
    "architecture_options": "b04_r6_major_router_architecture_options_matrix.json",
    "new_blind_candidate_set": "b04_r6_new_blind_universe_candidate_set.json",
    "v1_v2_family_autopsy": "b04_r6_v1_v2_candidate_family_autopsy.json",
    "static_dominance": "b04_r6_static_comparator_dominance_analysis.json",
    "abstention_first_draft": "b04_r6_abstention_first_router_contract_draft.json",
    "overrouting_containment_draft": "b04_r6_overrouting_containment_contract_draft.json",
    "calibration_gate_draft": "b04_r6_calibration_uncertainty_gate_contract_draft.json",
    "clean_state_watchdog": "b04_r6_redesign_clean_state_watchdog_receipt.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
    "report_md": "COHORT0_B04_R6_MAJOR_ROUTER_REDESIGN_SCOPE_REPORT.md",
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
    rows = payload.get("rows", payload.get("entries", payload.get("live_blockers_to_R6_open", [])))
    if not isinstance(rows, list):
        raise RuntimeError(f"FAIL_CLOSED: {label} missing rows/entries list")
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
        raise RuntimeError("FAIL_CLOSED: v1 must preserve guard law")

    if int(payloads["v2_receipt"].get("candidate_win_count", -1)) != 0:
        raise RuntimeError("FAIL_CLOSED: v2 must have zero candidate wins")
    if int(payloads["v2_receipt"].get("case_count", -1)) != 6:
        raise RuntimeError("FAIL_CLOSED: v2 must be the six-row blind screen")
    if int(payloads["v2_receipt"].get("disqualifier_count", -1)) != 3:
        raise RuntimeError("FAIL_CLOSED: v2 must carry three hard disqualifiers")

    forensic = payloads["forensic_receipt"]
    if forensic.get("cause_class") != "CANDIDATE_BEHAVIOR_DEFECT":
        raise RuntimeError("FAIL_CLOSED: redesign scope requires candidate-behavior forensic cause")
    if forensic.get("candidate_v2_disqualified_for_current_r6_screen_law") is not True:
        raise RuntimeError("FAIL_CLOSED: candidate v2 must be disqualified")

    rerun_bar = payloads["rerun_bar_receipt"]
    if rerun_bar.get("rerun_allowed") is not False or rerun_bar.get("rerun_bar_active") is not True:
        raise RuntimeError("FAIL_CLOSED: second shadow rerun must be barred")

    prior = payloads["prior_disqualification_receipt"]
    if prior.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: previous disqualification court did not authorize major redesign")
    if prior.get("current_candidate_family_retired") is not True:
        raise RuntimeError("FAIL_CLOSED: current candidate family must be retired")
    if prior.get("ordinary_candidate_v3_revision_allowed") is not False:
        raise RuntimeError("FAIL_CLOSED: ordinary candidate v3 revision must be barred")
    if prior.get("new_router_architecture_required") is not True:
        raise RuntimeError("FAIL_CLOSED: new router architecture must be required")
    if prior.get("new_blind_universe_required") is not True:
        raise RuntimeError("FAIL_CLOSED: new blind universe must be required")

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


def _candidate_family_retirement() -> Dict[str, Any]:
    return {
        "candidate_family": "minimal_deterministic_shadow_router_family_v1_v2",
        "retired_for_r6": True,
        "retirement_reason": "v1 failed superiority and v2 invalidated through candidate behavior disqualifiers.",
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
        },
        "quick_candidate_v3_forbidden": True,
        "second_shadow_screen_rerun_bar_active": True,
        "old_blind_universes_diagnostic_only": True,
    }


def _major_redesign_standard() -> Dict[str, Any]:
    return {
        "minimum_standard": "MATERIAL_ARCHITECTURE_CHANGE_REQUIRED",
        "threshold_or_weight_tweak_counts_as_major_redesign": False,
        "required_structural_changes": [
            "explicit_abstention_path",
            "static_hold_default",
            "overrouting_suppression",
            "hard_no_regression_control_plane",
        ],
        "acceptable_structural_families": [
            "ABSTENTION_FIRST_STATIC_HOLD_ROUTER",
            "UNCERTAINTY_GATED_CONFORMAL_ROUTER",
            "TWO_STAGE_PERFORMANCE_PREDICTOR_SELECTOR",
            "COST_AWARE_SELECTOR_WITH_STATIC_FALLBACK",
            "ENSEMBLE_GUARD_ROUTER_WITH_HARD_STATIC_FALLBACK",
        ],
        "forbidden_non_redesigns": [
            "quick_candidate_v3_patch",
            "weight_only_tuning",
            "threshold_only_tuning",
            "metric_widening",
            "static_baseline_weakening",
        ],
    }


def _router_requirements() -> Dict[str, Any]:
    return {
        "deterministic_replay_required": True,
        "seed_bound_behavior_required": True,
        "trace_emission_required": True,
        "explicit_abstention_required": True,
        "static_comparator_fallback_required": True,
        "overrouting_guard_required": True,
        "calibration_evidence_required": True,
        "mirror_masked_invariance_compatibility_required": True,
        "package_promotion_dependency_allowed": False,
        "truth_engine_or_trust_zone_mutation_dependency_allowed": False,
        "candidate_generation_authorized_by_this_packet": False,
    }


def _blind_universe_law() -> Dict[str, Any]:
    return {
        "new_blind_universe_required": True,
        "new_case_ids_required": True,
        "source_hashes_required": True,
        "family_coverage_required": True,
        "mirror_masked_sibling_policy_required": True,
        "holdout_separation_required": True,
        "leakage_scan_required": True,
        "v1_v2_outcomes_may_inform_architecture_diagnosis_only": True,
        "r01_r04_reuse_as_counted_proof_allowed": False,
        "six_row_blind_universe_reuse_as_fresh_proof_allowed": False,
        "new_blind_universe_selection_authorized_by_this_packet": False,
    }


def _comparator_metric_preservation() -> Dict[str, Any]:
    return {
        "static_baseline_weakening_allowed": False,
        "metric_widening_allowed": False,
        "disqualifier_softening_allowed": False,
        "comparator_contract_change_requires_separate_court": True,
        "existing_comparator_law_preserved": True,
    }


def _architecture_options() -> list[Dict[str, Any]]:
    return [
        {
            "option_id": "ABSTENTION_FIRST_STATIC_HOLD_ROUTER",
            "recommended_first_architecture_contract": True,
            "addresses": ["ABSTENTION_COLLAPSE", "OVERRouting_COLLAPSE", "CONTROL_DEGRADATION"],
            "default_action": "STATIC_HOLD",
            "eligible_for_next_architecture_contract": True,
        },
        {
            "option_id": "UNCERTAINTY_GATED_CONFORMAL_ROUTER",
            "recommended_first_architecture_contract": False,
            "addresses": ["ABSTENTION_COLLAPSE", "CONTROL_DEGRADATION"],
            "default_action": "STATIC_HOLD_ON_UNCERTAINTY",
            "eligible_for_next_architecture_contract": True,
        },
        {
            "option_id": "TWO_STAGE_PERFORMANCE_PREDICTOR_SELECTOR",
            "recommended_first_architecture_contract": False,
            "addresses": ["STATIC_COMPARATOR_DOMINANCE", "CONTROL_DEGRADATION"],
            "default_action": "PREDICT_THEN_SELECT_OR_STATIC_HOLD",
            "eligible_for_next_architecture_contract": True,
        },
        {
            "option_id": "COST_AWARE_SELECTOR_WITH_STATIC_FALLBACK",
            "recommended_first_architecture_contract": False,
            "addresses": ["OVERRouting_COLLAPSE", "CONTROL_DEGRADATION"],
            "default_action": "STATIC_HOLD_UNLESS_RISK_COST_MARGIN_PASSES",
            "eligible_for_next_architecture_contract": True,
        },
        {
            "option_id": "QUICK_CANDIDATE_V3_PATCH",
            "recommended_first_architecture_contract": False,
            "addresses": [],
            "eligible_for_next_architecture_contract": False,
            "rejection_reason": "Not a major redesign after v2 behavior disqualification.",
        },
    ]


def _new_blind_candidates() -> list[Dict[str, Any]]:
    return [
        {
            "candidate_set_id": "B04_R6_BLIND_UNIVERSE_CANDIDATE_SET_A_ADJACENT_FAMILY",
            "status": "PREP_ONLY_NOT_BOUND",
            "row_count": 8,
            "source_hashes_required_before_binding": True,
            "may_reuse_v1_or_v2_cases_as_counted_proof": False,
        },
        {
            "candidate_set_id": "B04_R6_BLIND_UNIVERSE_CANDIDATE_SET_B_MUTATED_SIBLINGS",
            "status": "PREP_ONLY_NOT_BOUND",
            "row_count": 8,
            "source_hashes_required_before_binding": True,
            "may_reuse_v1_or_v2_cases_as_counted_proof": False,
        },
    ]


def _blockers() -> list[Dict[str, Any]]:
    return [
        {
            "blocker_id": "ARCHITECTURE_CONTRACT_NOT_YET_BOUND",
            "severity": "BLOCKING_FOR_ANY_NEW_ROUTER_SOURCE",
            "resolution_path": NEXT_LAWFUL_MOVE,
        },
        {
            "blocker_id": "NEW_BLIND_UNIVERSE_NOT_YET_BOUND",
            "severity": "BLOCKING_FOR_ANY_NEW_SHADOW_SCREEN",
            "resolution_path": "AUTHOR_B04_R6_NEW_BLIND_INPUT_UNIVERSE_CONTRACT",
        },
        {
            "blocker_id": "OLD_BLIND_UNIVERSES_DIAGNOSTIC_ONLY",
            "severity": "BLOCKING_FOR_REUSE_AS_FRESH_PROOF",
            "resolution_path": "Bind new held-out proof universe.",
        },
        {
            "blocker_id": "CURRENT_CANDIDATE_FAMILY_RETIRED",
            "severity": "BLOCKING_FOR_QUICK_V3",
            "resolution_path": "Use major architecture court, not candidate patching.",
        },
    ]


def _report(selected_outcome: str, next_move: str) -> str:
    return (
        "# Cohort-0 B04 R6 Major Router Redesign Scope\n\n"
        f"Selected outcome: `{selected_outcome}`\n\n"
        "The v1/v2 minimal deterministic router family is retired for R6. Candidate v1 failed `0/4` "
        "with guards preserved. Candidate v2 failed `0/6` and triggered `CONTROL_DEGRADATION`, "
        "`ABSTENTION_COLLAPSE`, and `OVERRouting_COLLAPSE`; the forensic court confirmed "
        "`CANDIDATE_BEHAVIOR_DEFECT` and barred rerun.\n\n"
        "This packet authorizes scope for a major router redesign only. It does not authorize candidate "
        "generation, a new shadow screen, R6 opening, learned-router activation, lobe escalation, package "
        "promotion, metric widening, or comparator weakening.\n\n"
        f"Next lawful move: `{next_move}`\n"
    )


def run(*, reports_root: Path) -> Dict[str, Any]:
    root = repo_root()
    current_branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 major-router-redesign scope freeze")
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
    retirement = _candidate_family_retirement()
    redesign_standard = _major_redesign_standard()
    router_requirements = _router_requirements()
    blind_law = _blind_universe_law()
    comparator_law = _comparator_metric_preservation()
    options = _architecture_options()
    blockers = _blockers()

    common_decision = {
        "selected_outcome": SELECTED_OUTCOME,
        "allowed_outcomes": [OUTCOME_SCOPE_AUTHORIZED, OUTCOME_DEFERRED, OUTCOME_CLOSEOUT],
        "major_redesign_scope_authorized": True,
        "candidate_family_retired_for_r6": True,
        "quick_candidate_v3_forbidden": True,
        "candidate_generation_authorized": False,
        "new_shadow_screen_authorized": False,
        "new_router_architecture_required": True,
        "new_blind_universe_required": True,
        "architecture_contract_next": True,
        "blind_universe_contract_after_architecture": True,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }

    outputs: Dict[str, Any] = {
        OUTPUTS["scope_packet"]: {
            "schema_id": "kt.operator.b04_r6_major_router_redesign_scope_packet.v1",
            **base,
            **common_decision,
            "court_question": "Is major router redesign sufficiently scoped before architecture and blind-universe contracts?",
            "input_bindings": input_bindings,
            "candidate_family_retirement": retirement,
            "major_redesign_standard": redesign_standard,
            "new_router_family_requirements": router_requirements,
            "new_blind_universe_law": blind_law,
            "comparator_metric_preservation_law": comparator_law,
        },
        OUTPUTS["scope_receipt"]: {
            "schema_id": "kt.operator.b04_r6_major_router_redesign_scope_receipt.v1",
            **base,
            **common_decision,
            "status": "PASS",
            "verdict": SELECTED_OUTCOME,
        },
        OUTPUTS["candidate_family_retirement"]: {
            "schema_id": "kt.operator.b04_r6_candidate_family_retirement_receipt.v1",
            **base,
            **retirement,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["major_redesign_blocker_ledger"]: {
            "schema_id": "kt.operator.b04_r6_major_redesign_blocker_ledger.v1",
            **base,
            "live_blockers_to_r6_open": blockers,
            "live_blocker_count": len(blockers),
            "no_blockers_to_architecture_contract": True,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["architecture_options"]: {
            "schema_id": "kt.operator.b04_r6_major_router_architecture_options_matrix.v1",
            **base,
            "status": "PREP_ONLY",
            "options": options,
            "recommended_next_architecture_family": "ABSTENTION_FIRST_STATIC_HOLD_ROUTER",
            "candidate_generation_authorized": False,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["new_blind_candidate_set"]: {
            "schema_id": "kt.operator.b04_r6_new_blind_universe_candidate_set.v1",
            **base,
            "status": "PREP_ONLY",
            "candidate_sets": _new_blind_candidates(),
            "bound_universe_selected": False,
            "old_blind_universes_diagnostic_only": True,
            "next_lawful_move": "AUTHOR_B04_R6_NEW_BLIND_INPUT_UNIVERSE_CONTRACT",
        },
        OUTPUTS["v1_v2_family_autopsy"]: {
            "schema_id": "kt.operator.b04_r6_v1_v2_candidate_family_autopsy.v1",
            **base,
            **retirement,
            "family_level_conclusion": "STRUCTURAL_UNSAFE_OR_INSUFFICIENT_FOR_R6",
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["static_dominance"]: {
            "schema_id": "kt.operator.b04_r6_static_comparator_dominance_analysis.v3",
            **base,
            "status": "PREP_ONLY",
            "static_baseline_remains_control": True,
            "candidate_family_never_beat_static": True,
            "aggregate_candidate_wins": 0,
            "aggregate_counted_cases": 10,
            "static_baseline_weakening_allowed": False,
            "metric_widening_allowed": False,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["abstention_first_draft"]: {
            "schema_id": "kt.operator.b04_r6_abstention_first_router_contract_draft.v1",
            **base,
            "status": "PREP_ONLY",
            "default_action": "STATIC_HOLD",
            "route_only_if": ["eligibility_gate_passes", "calibration_margin_passes", "mirror_masked_stability_passes"],
            "candidate_generation_authorized": False,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["overrouting_containment_draft"]: {
            "schema_id": "kt.operator.b04_r6_overrouting_containment_contract_draft.v1",
            **base,
            "status": "PREP_ONLY",
            "hard_controls": ["route_rate_ceiling", "static_hold_floor", "overrouting_risk_trace"],
            "disqualifier_softening_allowed": False,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["calibration_gate_draft"]: {
            "schema_id": "kt.operator.b04_r6_calibration_uncertainty_gate_contract_draft.v1",
            **base,
            "status": "PREP_ONLY",
            "required_receipts": ["calibration_source_receipt", "uncertainty_threshold_contract", "coverage_guard_receipt"],
            "static_hold_on_uncertainty": True,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["clean_state_watchdog"]: {
            "schema_id": "kt.operator.b04_r6_redesign_clean_state_watchdog_receipt.v1",
            **base,
            "status": "PASS",
            "package_promotion_drift": False,
            "truth_engine_mutation_detected": False,
            "trust_zone_mutation_detected": False,
            "old_blind_universe_reuse_detected": False,
            "candidate_generation_before_architecture_law_detected": False,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["next_lawful_move"]: {
            "schema_id": "kt.operator.b04_r6_next_lawful_move_receipt.v2",
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
    parser = argparse.ArgumentParser(description="Freeze B04 R6 major router redesign scope court.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(reports_root=common.resolve_path(root, args.reports_root))
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
