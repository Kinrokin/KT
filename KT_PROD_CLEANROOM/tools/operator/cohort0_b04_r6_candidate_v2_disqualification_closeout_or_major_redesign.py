from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-v2-disqualification-closeout-redesign"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_CANDIDATE_V2_DISQUALIFICATION_AND_CLOSEOUT_OR_MAJOR_REDESIGN"
PREVIOUS_LANE = "B04_R6_SECOND_SHADOW_SCREEN_FORENSIC_AND_RERUN_BAR"

V1_VERDICT = "R6_SHADOW_SUPERIORITY_FAILED__LEARNED_ROUTER_SUPERIORITY_NOT_EARNED"
V2_VERDICT = "R6_SECOND_SHADOW_SCREEN_INVALIDATED__DISQUALIFIER_TRIGGERED"
FORENSIC_VERDICT = "R6_SECOND_SHADOW_INVALIDATION_CONFIRMED__CANDIDATE_V2_DISQUALIFIED"
EXPECTED_PREVIOUS_NEXT_MOVE = "AUTHOR_B04_R6_CANDIDATE_V2_DISQUALIFICATION_AND_CLOSEOUT_OR_MAJOR_REDESIGN_PACKET"

OUTCOME_CLOSEOUT = "R6_CLOSEOUT__LEARNED_ROUTER_SUPERIORITY_NOT_EARNED_ON_CURRENT_SUBSTRATE"
OUTCOME_MAJOR_REDESIGN = "R6_MAJOR_REDESIGN_AUTHORIZED__NEW_ROUTER_ARCHITECTURE_AND_NEW_BLIND_UNIVERSE_REQUIRED"
OUTCOME_DEFERRED = "R6_DEFERRED__AWAITING_NEW_FEATURE_SUBSTRATE_OR_ROUTER_FAMILY"
SELECTED_OUTCOME = OUTCOME_MAJOR_REDESIGN
NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_MAJOR_ROUTER_REDESIGN_SCOPE_PACKET__NEW_ARCHITECTURE_AND_NEW_BLIND_UNIVERSE_REQUIRED"

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
    "v1_scorecard": "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_superiority_scorecard.json",
    "v1_disqualifier_ledger": "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_disqualifier_ledger.json",
    "v2_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_second_shadow_screen_result_receipt.json",
    "v2_scorecard": "KT_PROD_CLEANROOM/reports/b04_r6_second_shadow_scorecard.json",
    "v2_disqualifier_ledger": "KT_PROD_CLEANROOM/reports/b04_r6_second_shadow_disqualifier_ledger.json",
    "forensic_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_second_shadow_screen_forensic_receipt.json",
    "rerun_bar_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_second_shadow_screen_rerun_bar_receipt.json",
    "guard_failure_matrix": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v2_guard_failure_matrix.json",
    "v2_overrouting_autopsy": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v2_overrouting_autopsy.json",
    "v2_abstention_autopsy": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v2_abstention_collapse_autopsy.json",
    "v2_control_autopsy": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v2_control_degradation_autopsy.json",
}

HANDOFF_INPUTS = {
    "previous_next_lawful_move": "KT_PROD_CLEANROOM/reports/b04_r6_next_lawful_move_receipt.json",
}

OUTPUTS = {
    "disqualification_packet": "b04_r6_candidate_v2_disqualification_packet.json",
    "disqualification_receipt": "b04_r6_candidate_v2_disqualification_receipt.json",
    "candidate_family_autopsy": "b04_r6_candidate_family_autopsy.json",
    "static_comparator_dominance": "b04_r6_static_comparator_dominance_analysis.json",
    "major_redesign_options": "b04_r6_major_redesign_options_matrix.json",
    "blocker_ledger": "b04_r6_closeout_or_major_redesign_blocker_ledger.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
    "report_md": "COHORT0_B04_R6_CANDIDATE_V2_DISQUALIFICATION_CLOSEOUT_OR_MAJOR_REDESIGN_REPORT.md",
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
    rows = payload.get("rows", payload.get("entries", []))
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

    if payloads["v1_receipt"].get("verdict") != V1_VERDICT:
        raise RuntimeError("FAIL_CLOSED: v1 must be the clean failed-superiority screen")
    if payloads["v1_scorecard"].get("screen_verdict") != V1_VERDICT:
        raise RuntimeError("FAIL_CLOSED: v1 scorecard verdict mismatch")
    if int(payloads["v1_receipt"].get("candidate_win_count", -1)) != 0:
        raise RuntimeError("FAIL_CLOSED: v1 must have zero candidate wins")
    if int(payloads["v1_receipt"].get("case_count", -1)) != 4:
        raise RuntimeError("FAIL_CLOSED: v1 must be the four-row first screen")
    if int(payloads["v1_receipt"].get("disqualifier_count", -1)) != 0:
        raise RuntimeError("FAIL_CLOSED: v1 must have no disqualifiers")
    if int(payloads["v1_disqualifier_ledger"].get("triggered_count", 0)) != 0:
        raise RuntimeError("FAIL_CLOSED: v1 disqualifier ledger must be clean")

    if payloads["v2_receipt"].get("verdict") != V2_VERDICT:
        raise RuntimeError("FAIL_CLOSED: v2 must be the invalidated second shadow screen")
    if payloads["v2_scorecard"].get("screen_verdict") != V2_VERDICT:
        raise RuntimeError("FAIL_CLOSED: v2 scorecard verdict mismatch")
    if int(payloads["v2_receipt"].get("candidate_win_count", -1)) != 0:
        raise RuntimeError("FAIL_CLOSED: v2 must have zero candidate wins")
    if int(payloads["v2_receipt"].get("case_count", -1)) != 6:
        raise RuntimeError("FAIL_CLOSED: v2 must be the six-row blind screen")
    if int(payloads["v2_receipt"].get("disqualifier_count", -1)) != 3:
        raise RuntimeError("FAIL_CLOSED: v2 must carry three disqualifiers")

    forensic = payloads["forensic_receipt"]
    if forensic.get("verdict") != FORENSIC_VERDICT:
        raise RuntimeError("FAIL_CLOSED: forensic court must confirm candidate-v2 disqualification")
    if forensic.get("cause_class") != "CANDIDATE_BEHAVIOR_DEFECT":
        raise RuntimeError("FAIL_CLOSED: closeout-or-redesign court requires candidate behavior cause")
    if forensic.get("candidate_v2_disqualified_for_current_r6_screen_law") is not True:
        raise RuntimeError("FAIL_CLOSED: candidate v2 must be disqualified")

    rerun_bar = payloads["rerun_bar_receipt"]
    if rerun_bar.get("rerun_allowed") is not False or rerun_bar.get("rerun_bar_active") is not True:
        raise RuntimeError("FAIL_CLOSED: second shadow rerun must be barred")
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


def _family_autopsy(payloads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    guard_rows = _rows(payloads["guard_failure_matrix"], label="guard failure matrix")
    implicated = [row for row in guard_rows if row.get("cause_class") == "CANDIDATE_BEHAVIOR_DEFECT"]
    return {
        "v1": {
            "candidate_id": "b04_r6_minimal_deterministic_shadow_router_v1",
            "candidate_wins": 0,
            "case_count": 4,
            "disqualifier_count": 0,
            "result": "CLEAN_CAPABILITY_FAILURE",
            "guard_law_preserved": True,
        },
        "v2": {
            "candidate_id": "b04_r6_diagnostic_gap_shadow_router_v2",
            "candidate_wins": 0,
            "case_count": 6,
            "disqualifier_count": 3,
            "result": "INVALIDATED_BY_CANDIDATE_BEHAVIOR",
            "guard_law_preserved": False,
            "implicated_cases": [row.get("case_id") for row in implicated],
            "triggered_guard_failures": [
                "CONTROL_DEGRADATION",
                "ABSTENTION_COLLAPSE",
                "OVERRouting_COLLAPSE",
            ],
        },
        "family_assessment": "CURRENT_MINIMAL_DETERMINISTIC_ROUTER_FAMILY_RETIRED_FOR_R6",
        "quick_candidate_v3_allowed": False,
        "ordinary_revision_allowed": False,
        "major_redesign_required_for_any_future_R6_attempt": True,
    }


def _static_dominance() -> Dict[str, Any]:
    return {
        "v1_static_comparator_dominance": True,
        "v2_static_comparator_dominance": True,
        "candidate_family_never_beat_static": True,
        "aggregate_candidate_wins": 0,
        "aggregate_counted_cases": 10,
        "static_baseline_weakening_allowed": False,
        "metric_widening_allowed": False,
        "interpretation": (
            "The current learned-router family produced zero wins across both counted screens. "
            "The static comparator remains the lawful control and may not be weakened to create movement."
        ),
    }


def _redesign_options() -> list[Dict[str, Any]]:
    return [
        {
            "option_id": "ABSTENTION_FIRST_STATIC_HOLD_ROUTER",
            "materially_different_from_v1_v2": True,
            "addresses": ["ABSTENTION_COLLAPSE", "OVERRouting_COLLAPSE"],
            "required_new_evidence": ["new_architecture_source_packet", "new_blind_universe", "static_hold_proof"],
            "candidate_generation_authorized_now": False,
            "admissible_for_next_scope_court": True,
        },
        {
            "option_id": "UNCERTAINTY_GATED_CONFORMAL_ROUTER",
            "materially_different_from_v1_v2": True,
            "addresses": ["ABSTENTION_COLLAPSE", "CONTROL_DEGRADATION"],
            "required_new_evidence": ["calibration_receipt", "coverage_threshold_contract", "new_blind_universe"],
            "candidate_generation_authorized_now": False,
            "admissible_for_next_scope_court": True,
        },
        {
            "option_id": "TWO_STAGE_PERFORMANCE_PREDICTOR_SELECTOR",
            "materially_different_from_v1_v2": True,
            "addresses": ["STATIC_COMPARATOR_DOMINANCE", "CONTROL_DEGRADATION"],
            "required_new_evidence": ["feature_substrate_receipt", "predictor_holdout_receipt", "new_blind_universe"],
            "candidate_generation_authorized_now": False,
            "admissible_for_next_scope_court": True,
        },
        {
            "option_id": "COST_AWARE_SELECTOR_WITH_STATIC_FALLBACK",
            "materially_different_from_v1_v2": True,
            "addresses": ["OVERRouting_COLLAPSE", "CONTROL_DEGRADATION"],
            "required_new_evidence": ["cost_contract", "fallback_preservation_receipt", "new_blind_universe"],
            "candidate_generation_authorized_now": False,
            "admissible_for_next_scope_court": True,
        },
        {
            "option_id": "QUICK_CANDIDATE_V3_PATCH",
            "materially_different_from_v1_v2": False,
            "addresses": [],
            "required_new_evidence": [],
            "candidate_generation_authorized_now": False,
            "admissible_for_next_scope_court": False,
            "rejection_reason": "A patch-style v3 would reuse a disqualified family and risks overfitting invalidated screen evidence.",
        },
    ]


def _blockers() -> list[Dict[str, Any]]:
    return [
        {
            "blocker_id": "CURRENT_CANDIDATE_FAMILY_RETIRED",
            "severity": "BLOCKING_FOR_QUICK_REVISION",
            "resolution_path": "Major redesign scope court only.",
        },
        {
            "blocker_id": "NEW_ROUTER_ARCHITECTURE_REQUIRED",
            "severity": "BLOCKING_FOR_NEXT_CANDIDATE",
            "resolution_path": "Author architecture-level scope packet before any candidate generation.",
        },
        {
            "blocker_id": "NEW_BLIND_UNIVERSE_REQUIRED",
            "severity": "BLOCKING_FOR_NEXT_SCREEN",
            "resolution_path": "Bind a new blind input universe; v1 and v2 screens are diagnostic only.",
        },
        {
            "blocker_id": "SECOND_SCREEN_RERUN_BAR_ACTIVE",
            "severity": "BLOCKING_FOR_RERUN",
            "resolution_path": "No rerun unless a later court proves non-candidate forensic defect.",
        },
    ]


def _report(selected_outcome: str, next_move: str) -> str:
    return (
        "# Cohort-0 B04 R6 Candidate V2 Disqualification Closeout Or Major Redesign\n\n"
        f"Selected outcome: `{selected_outcome}`\n\n"
        "Candidate v1 failed `0/4` with guards preserved. Candidate v2 failed `0/6` and triggered "
        "`CONTROL_DEGRADATION`, `ABSTENTION_COLLAPSE`, and `OVERRouting_COLLAPSE`. The forensic court "
        "confirmed candidate behavior as the cause, so v2 is disqualified and the second screen rerun is barred.\n\n"
        "This court does not authorize candidate v3 generation, R6 opening, learned-router activation, lobe escalation, "
        "package promotion, metric widening, or comparator weakening.\n\n"
        f"Next lawful move: `{next_move}`\n"
    )


def run(*, reports_root: Path) -> Dict[str, Any]:
    root = repo_root()
    current_branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 closeout-or-major-redesign freeze")
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
    family_autopsy = _family_autopsy(payloads)
    static_dominance = _static_dominance()
    redesign_options = _redesign_options()
    blockers = _blockers()

    common_decision = {
        "selected_outcome": SELECTED_OUTCOME,
        "allowed_outcomes": [OUTCOME_CLOSEOUT, OUTCOME_MAJOR_REDESIGN, OUTCOME_DEFERRED],
        "current_candidate_family_retired": True,
        "ordinary_candidate_v3_revision_allowed": False,
        "candidate_generation_authorized": False,
        "new_shadow_screen_authorized": False,
        "second_shadow_screen_rerun_allowed": False,
        "six_row_blind_universe_reuse_as_fresh_proof_allowed": False,
        "current_substrate_r6_closeout_selected": False,
        "major_redesign_authorized": True,
        "new_router_architecture_required": True,
        "new_blind_universe_required": True,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }

    outputs: Dict[str, Any] = {
        OUTPUTS["disqualification_packet"]: {
            "schema_id": "kt.operator.b04_r6_candidate_v2_disqualification_packet.v1",
            **base,
            **common_decision,
            "court_question": "Should R6 close on the current substrate, defer, or authorize a major router redesign?",
            "input_bindings": input_bindings,
            "v1_result": "0/4 wins, no disqualifiers",
            "v2_result": "0/6 wins, three disqualifiers",
            "forensic_cause": "CANDIDATE_BEHAVIOR_DEFECT",
        },
        OUTPUTS["disqualification_receipt"]: {
            "schema_id": "kt.operator.b04_r6_candidate_v2_disqualification_receipt.v1",
            **base,
            **common_decision,
            "status": "PASS",
            "candidate_v2_disqualified": True,
            "rerun_bar_active": True,
            "verdict": SELECTED_OUTCOME,
        },
        OUTPUTS["candidate_family_autopsy"]: {
            "schema_id": "kt.operator.b04_r6_candidate_family_autopsy.v1",
            **base,
            **family_autopsy,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["static_comparator_dominance"]: {
            "schema_id": "kt.operator.b04_r6_static_comparator_dominance_analysis.v2",
            **base,
            **static_dominance,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["major_redesign_options"]: {
            "schema_id": "kt.operator.b04_r6_major_redesign_options_matrix.v1",
            **base,
            "selected_path": "MAJOR_REDESIGN_SCOPE_COURT",
            "quick_candidate_v3_patch_allowed": False,
            "options": redesign_options,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["blocker_ledger"]: {
            "schema_id": "kt.operator.b04_r6_closeout_or_major_redesign_blocker_ledger.v1",
            **base,
            "live_blockers_to_R6_open": blockers,
            "live_blocker_count": len(blockers),
            "no_blockers_to_major_redesign_scope_packet": True,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["next_lawful_move"]: {
            "schema_id": "kt.operator.b04_r6_next_lawful_move_receipt.v1",
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
    parser = argparse.ArgumentParser(description="Freeze B04 R6 candidate-v2 disqualification closeout/major-redesign court.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(reports_root=common.resolve_path(root, args.reports_root))
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
