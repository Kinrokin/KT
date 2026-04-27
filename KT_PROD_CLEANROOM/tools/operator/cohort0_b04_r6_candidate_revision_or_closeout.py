from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable


REQUIRED_BRANCH = "authoritative/b04-r6-candidate-revision-or-closeout"
AUTHORITATIVE_LANE = "B04_R6_CANDIDATE_REVISION_OR_CLOSEOUT"
PREVIOUS_LANE = "B04_R6_SHADOW_ROUTER_SUPERIORITY_SCREEN_EXECUTION"

EXPECTED_PREVIOUS_VERDICT = "R6_SHADOW_SUPERIORITY_FAILED__LEARNED_ROUTER_SUPERIORITY_NOT_EARNED"
EXPECTED_PREVIOUS_NEXT_MOVE = "AUTHOR_B04_R6_CANDIDATE_REVISION_OR_CLOSEOUT_PACKET"
FINAL_VERDICT = "R6_DEFERRED__NEEDS_NEW_BLIND_INPUT_UNIVERSE_FOR_REVISION"
NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_CANDIDATE_REVISION_PACKET__NEW_BLIND_INPUT_UNIVERSE_REQUIRED"

FORBIDDEN_FINAL_VERDICTS = [
    "R6_OPEN",
    "LEARNED_ROUTER_SUPERIORITY_EARNED",
    "LEARNED_ROUTER_ACTIVATED",
    "MULTI_LOBE_AUTHORIZED",
    "PACKAGE_PROMOTION_APPROVED",
]

OUTPUTS = {
    "authority_packet": "b04_r6_candidate_revision_or_closeout_packet.json",
    "authority_receipt": "b04_r6_candidate_revision_or_closeout_receipt.json",
    "failure_autopsy_packet": "b04_r6_shadow_failure_autopsy_packet.json",
    "failure_autopsy_receipt": "b04_r6_shadow_failure_autopsy_receipt.json",
    "per_row_failure_matrix": "b04_r6_per_row_failure_matrix.json",
    "candidate_static_delta_matrix": "b04_r6_candidate_static_delta_matrix.json",
    "revision_eligibility_packet": "b04_r6_candidate_revision_eligibility_packet.json",
    "revision_eligibility_receipt": "b04_r6_candidate_revision_eligibility_receipt.json",
    "revision_blocker_ledger": "b04_r6_candidate_revision_blocker_ledger.json",
    "next_screen_input_policy_packet": "b04_r6_next_screen_input_policy_packet.json",
    "blind_input_requirement_receipt": "b04_r6_blind_input_requirement_receipt.json",
    "next_lawful_move_receipt": "b04_r6_candidate_revision_next_lawful_move_receipt.json",
    "report_md": "COHORT0_B04_R6_CANDIDATE_REVISION_OR_CLOSEOUT_REPORT.md",
}

INPUTS = {
    "screen_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_superiority_screen_receipt.json",
    "scorecard": "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_superiority_scorecard.json",
    "route_matrix": "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_route_trace_matrix.json",
    "abstention_matrix": "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_abstention_overrouting_matrix.json",
    "invariance_matrix": "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_mirror_masked_invariance_matrix.json",
    "disqualifier_ledger": "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_disqualifier_ledger.json",
    "superiority_blocker_ledger": "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_superiority_blocker_ledger.json",
    "previous_next_lawful_move": "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_next_lawful_move_receipt.json",
}


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


def _ensure_false(payload: Dict[str, Any], key: str, *, label: str) -> None:
    if key in payload and payload.get(key) is not False:
        raise RuntimeError(f"FAIL_CLOSED: {label} must keep {key}=false")


def _ensure_boundaries(payload: Dict[str, Any], *, label: str) -> None:
    if str(payload.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: {label} must have status PASS")
    for key in (
        "r6_authorized",
        "r6_open",
        "learned_router_superiority_earned",
        "learned_router_activated",
        "multi_lobe_authorized",
    ):
        _ensure_false(payload, key, label=label)
    if payload.get("package_promotion_remains_deferred") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve package promotion deferral")
    if payload.get("truth_engine_derivation_law_unchanged") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve truth-engine law")
    if payload.get("trust_zone_law_unchanged") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve trust-zone law")


def _base(*, generated_utc: str, head: str, subject_main_head: str) -> Dict[str, Any]:
    return {
        "status": "PASS",
        "generated_utc": generated_utc,
        "current_git_head": head,
        "subject_main_head": subject_main_head,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "forbidden_final_verdicts": FORBIDDEN_FINAL_VERDICTS,
        "r6_authorized": False,
        "r6_open": False,
        "learned_router_superiority_earned": False,
        "learned_router_activated": False,
        "learned_router_cutover_authorized": False,
        "multi_lobe_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _require_previous_screen(payloads: Dict[str, Dict[str, Any]]) -> None:
    receipt = payloads["screen_receipt"]
    scorecard = payloads["scorecard"]
    disqualifiers = payloads["disqualifier_ledger"]
    previous_next = payloads["previous_next_lawful_move"]
    for label, payload in payloads.items():
        _ensure_boundaries(payload, label=label)
    if receipt.get("verdict") != EXPECTED_PREVIOUS_VERDICT:
        raise RuntimeError("FAIL_CLOSED: previous R6 screen must be a clean failed-superiority verdict")
    if scorecard.get("screen_verdict") != EXPECTED_PREVIOUS_VERDICT:
        raise RuntimeError("FAIL_CLOSED: scorecard must match the failed-superiority verdict")
    if int(receipt.get("candidate_win_count", -1)) != 0 or int(scorecard.get("candidate_win_count", -1)) != 0:
        raise RuntimeError("FAIL_CLOSED: revision-or-closeout court is only for the zero-win failed screen")
    if int(receipt.get("case_count", 0)) <= 0:
        raise RuntimeError("FAIL_CLOSED: previous screen case count must be positive")
    if int(receipt.get("disqualifier_count", -1)) != 0:
        raise RuntimeError("FAIL_CLOSED: disqualified screens require forensic handling, not revision court")
    if int(disqualifiers.get("triggered_count", -1)) != 0 or disqualifiers.get("entries"):
        raise RuntimeError("FAIL_CLOSED: disqualified screens require forensic handling, not revision court")
    if receipt.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        raise RuntimeError("FAIL_CLOSED: previous screen did not authorize candidate revision-or-closeout")
    if previous_next.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        raise RuntimeError("FAIL_CLOSED: previous next-lawful-move receipt mismatch")
    metrics = dict(scorecard.get("metrics", {}))
    for metric_id in ("control_preservation", "abstention_quality", "overrouting_penalty", "mirror_masked_invariance", "no_regression"):
        if dict(metrics.get(metric_id, {})).get("result") != "PASS":
            raise RuntimeError(f"FAIL_CLOSED: previous screen guard did not pass: {metric_id}")


def _hash_inputs(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in sorted(INPUTS.items()):
        path = root / raw
        if not path.is_file():
            raise RuntimeError(f"FAIL_CLOSED: missing required input: {raw}")
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    return rows


def _rows(payload: Dict[str, Any], *, label: str) -> list[Dict[str, Any]]:
    rows = payload.get("rows")
    if not isinstance(rows, list):
        raise RuntimeError(f"FAIL_CLOSED: {label} missing rows list")
    return [dict(row) for row in rows if isinstance(row, dict)]


def _by_case(rows: list[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        case_id = str(row.get("case_id", "")).strip()
        if case_id:
            out[case_id] = row
    return out


def _failure_diagnostics(
    *,
    route_rows: list[Dict[str, Any]],
    abstention_rows: list[Dict[str, Any]],
    invariance_rows: list[Dict[str, Any]],
    scorecard: Dict[str, Any],
) -> Dict[str, Any]:
    case_count = int(scorecard.get("case_count", len(route_rows)))
    candidate_win_count = int(scorecard.get("candidate_win_count", 0))
    route_set_match_count = sum(1 for row in route_rows if row.get("route_set_match") is True)
    exact_order_mismatch_count = sum(1 for row in route_rows if row.get("exact_order_match") is False)
    abstention_failure_count = sum(1 for row in abstention_rows if row.get("static_hold_preserved") is not True)
    overroute_count = sum(1 for row in abstention_rows if row.get("overrouting_detected") is True)
    invariance_failure_count = sum(1 for row in invariance_rows if row.get("invariance_pass") is not True)
    no_useful_delta = dict(dict(scorecard.get("metrics", {})).get("outcome_delta", {})).get("result") == "NO_USEFUL_OUTPUT_DELTA_EVIDENCE_BOUND"
    return {
        "candidate_win_count": candidate_win_count,
        "case_count": case_count,
        "route_set_match_count": route_set_match_count,
        "exact_order_mismatch_count": exact_order_mismatch_count,
        "abstention_failure_count": abstention_failure_count,
        "overrouting_failure_count": overroute_count,
        "mirror_masked_failure_count": invariance_failure_count,
        "failure_classes": {
            "route_choice_failures": route_set_match_count != case_count,
            "abstention_failures": abstention_failure_count > 0 or overroute_count > 0,
            "feature_insufficiency": candidate_win_count == 0 and no_useful_delta,
            "static_comparator_dominance": candidate_win_count == 0 and route_set_match_count == case_count,
            "candidate_underfitting": candidate_win_count == 0 and route_set_match_count == case_count,
            "screen_size_limitation": case_count <= 4,
            "metric_contract_mismatch": False,
        },
        "clean_failure": True,
    }


def _per_row_failure_matrix(route_rows: list[Dict[str, Any]], abstention_rows: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    abstention_by_case = _by_case(abstention_rows)
    rows: list[Dict[str, Any]] = []
    for route in route_rows:
        case_id = str(route.get("case_id", "")).strip()
        abstention = abstention_by_case.get(case_id, {})
        finding = "STATIC_MATCH_NO_SUPERIORITY"
        notes: list[str] = []
        if route.get("route_set_match") is not True:
            finding = "ROUTE_SET_REGRESSION"
            notes.append("Candidate route set did not match static comparator.")
        if route.get("order_advisory") is True:
            notes.append("Candidate matched the static route set but order differed; advisory only.")
        if abstention.get("static_hold_preserved") is True and abstention.get("candidate_abstained") is True:
            notes.append("Candidate preserved static-hold abstention but did not create superiority evidence.")
        rows.append(
            {
                "case_id": case_id,
                "family": route.get("family"),
                "baseline_adapter_ids": route.get("baseline_adapter_ids", []),
                "candidate_adapter_ids": route.get("candidate_adapter_ids", []),
                "candidate_beats_static": bool(route.get("candidate_beats_static", False)),
                "route_quality_delta": route.get("route_quality_delta", 0),
                "route_set_match": bool(route.get("route_set_match", False)),
                "exact_order_match": bool(route.get("exact_order_match", False)),
                "abstention_static_hold_preserved": bool(abstention.get("static_hold_preserved", False)),
                "diagnostic_finding": finding,
                "notes": notes,
                "diagnostic_use_allowed": True,
                "reuse_as_counted_superiority_row_after_revision": False,
            }
        )
    return rows


def _report(verdict: str, diagnostics: Dict[str, Any]) -> str:
    classes = dict(diagnostics["failure_classes"])
    return (
        "# Cohort-0 B04 R6 Candidate Revision Or Closeout\n\n"
        f"Verdict: `{verdict}`\n\n"
        "The first admissible learned-router candidate remains lawful but failed the frozen R6 shadow superiority screen. "
        "The failure is clean: no disqualifiers, no control degradation, no abstention collapse, and no truth-law mutation. "
        "The current R01-R04 screen is closed as proof substrate for any revised candidate that learns from this failure.\n\n"
        f"Candidate wins over static: `{diagnostics['candidate_win_count']}` of `{diagnostics['case_count']}`.\n\n"
        f"Static comparator dominance: `{classes['static_comparator_dominance']}`.\n\n"
        f"Next lawful move: `{NEXT_LAWFUL_MOVE}`.\n"
    )


def run(*, reports_root: Path) -> Dict[str, Any]:
    root = repo_root()
    if common.git_current_branch_name(root) != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: must run on {REQUIRED_BRANCH}")
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 revision-or-closeout court")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    payloads = {role: _load(root, raw, label=role) for role, raw in INPUTS.items()}
    _require_previous_screen(payloads)
    generated_utc = utc_now_iso_z()
    head = common.git_rev_parse(root, "HEAD")
    subject_main_head = str(payloads["screen_receipt"].get("current_git_head", "")).strip()
    input_hashes = _hash_inputs(root)
    route_rows = _rows(payloads["route_matrix"], label="route matrix")
    abstention_rows = _rows(payloads["abstention_matrix"], label="abstention matrix")
    invariance_rows = _rows(payloads["invariance_matrix"], label="invariance matrix")
    diagnostics = _failure_diagnostics(
        route_rows=route_rows,
        abstention_rows=abstention_rows,
        invariance_rows=invariance_rows,
        scorecard=payloads["scorecard"],
    )
    per_row = _per_row_failure_matrix(route_rows, abstention_rows)
    base = _base(generated_utc=generated_utc, head=head, subject_main_head=subject_main_head)

    authority_packet = {
        "schema_id": "kt.operator.b04_r6_candidate_revision_or_closeout_packet.v1",
        **base,
        "court_question": "Should R6 close on the current substrate, authorize candidate revision, or defer until a new blind input universe exists?",
        "previous_screen_verdict": EXPECTED_PREVIOUS_VERDICT,
        "previous_result": {
            "candidate_wins_over_static": "0/4",
            "disqualifiers_triggered": 0,
            "controls_preserved": True,
            "abstention_quality_passed": True,
            "mirror_masked_invariance_passed": True,
        },
        "allowed_outcomes": [
            "AUTHOR_R6_CANDIDATE_REVISION_PACKET",
            "R6_CLOSEOUT__LEARNED_ROUTER_SUPERIORITY_NOT_EARNED_ON_CURRENT_SUBSTRATE",
            "R6_DEFERRED__NEEDS_NEW_BLIND_INPUT_UNIVERSE_FOR_REVISION",
        ],
        "selected_outcome": FINAL_VERDICT,
        "input_bindings": input_hashes,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    failure_autopsy_packet = {
        "schema_id": "kt.operator.b04_r6_shadow_failure_autopsy_packet.v1",
        **base,
        "diagnostics": diagnostics,
        "per_row_failure_matrix_ref": OUTPUTS["per_row_failure_matrix"],
        "candidate_static_delta_matrix_ref": OUTPUTS["candidate_static_delta_matrix"],
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    failure_autopsy_receipt = {
        "schema_id": "kt.operator.b04_r6_shadow_failure_autopsy_receipt.v1",
        **base,
        "autopsy_complete": True,
        "clean_failure": diagnostics["clean_failure"],
        "failure_classes": diagnostics["failure_classes"],
        "candidate_wins_over_static": "0/4",
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    per_row_failure_matrix = {
        "schema_id": "kt.operator.b04_r6_per_row_failure_matrix.v1",
        **base,
        "rows": per_row,
        "same_rows_reusable_for_revised_candidate_counted_screen": False,
        "diagnostic_use_allowed": True,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    candidate_static_delta_matrix = {
        "schema_id": "kt.operator.b04_r6_candidate_static_delta_matrix.v1",
        **base,
        "summary": {
            "candidate_win_count": diagnostics["candidate_win_count"],
            "case_count": diagnostics["case_count"],
            "route_set_match_count": diagnostics["route_set_match_count"],
            "route_quality_delta_sum": sum(int(row.get("route_quality_delta", 0)) for row in route_rows),
            "superiority_delta": 0,
            "static_comparator_dominance": diagnostics["failure_classes"]["static_comparator_dominance"],
        },
        "rows": per_row,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    revision_eligibility_packet = {
        "schema_id": "kt.operator.b04_r6_candidate_revision_eligibility_packet.v1",
        **base,
        "current_candidate_revision_eligible_for_diagnostic_design": True,
        "current_candidate_is_admissible_but_weak": True,
        "candidate_v2_generation_authorized_by_this_packet": False,
        "screen_execution_authorized_by_this_packet": False,
        "plausible_revision_hypotheses": [
            "feature_insufficiency",
            "candidate_underfitting",
            "static_comparator_dominance_requires_non-overfit delta evidence",
        ],
        "closure_recommended_now": False,
        "selected_outcome": FINAL_VERDICT,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    revision_eligibility_receipt = {
        "schema_id": "kt.operator.b04_r6_candidate_revision_eligibility_receipt.v1",
        **base,
        "revision_eligibility_court_complete": True,
        "revision_path_plausible": True,
        "same_r01_r04_reuse_for_counted_superiority_screen_allowed": False,
        "new_blind_input_universe_required": True,
        "selected_outcome": FINAL_VERDICT,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    revision_blocker_ledger = {
        "schema_id": "kt.operator.b04_r6_candidate_revision_blocker_ledger.v1",
        **base,
        "entries": [
            {
                "blocker_id": "B04_R6_LEARNED_ROUTER_SUPERIORITY_NOT_EARNED_ON_CURRENT_SCREEN",
                "status": "LIVE",
                "severity": "BLOCKS_R6_OPEN",
                "resolution_path": NEXT_LAWFUL_MOVE,
            },
            {
                "blocker_id": "B04_R6_NEXT_COUNTED_SCREEN_REQUIRES_NEW_BLIND_INPUT_UNIVERSE",
                "status": "LIVE",
                "severity": "BLOCKS_RERUN_ON_R01_R04",
                "resolution_path": "AUTHOR_B04_R6_NEXT_BLIND_INPUT_UNIVERSE_PACKET",
            },
        ],
        "live_blocker_count": 2,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    next_screen_input_policy_packet = {
        "schema_id": "kt.operator.b04_r6_next_screen_input_policy_packet.v1",
        **base,
        "r01_r04_use_policy": {
            "diagnostic_use_allowed": True,
            "training_directly_on_failure_outcomes_for_same_counted_screen_allowed": False,
            "reuse_as_counted_superiority_screen_after_revision_allowed": False,
        },
        "next_counted_screen_requirements": [
            "new blind input universe or mutation policy must be frozen before candidate v2 counted screen",
            "source/holdout separation must be re-proven",
            "candidate v2 must not train on next-screen labels",
            "comparator and metric contracts must remain immutable unless a later court authorizes supersession",
        ],
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    blind_input_requirement_receipt = {
        "schema_id": "kt.operator.b04_r6_blind_input_requirement_receipt.v1",
        **base,
        "new_blind_input_universe_required": True,
        "reason": "Any revised candidate informed by R01-R04 failure outcomes would contaminate a repeated counted superiority screen on the same rows.",
        "r01_r04_closed_for_candidate_v2_counted_superiority_rerun": True,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    authority_receipt = {
        "schema_id": "kt.operator.b04_r6_candidate_revision_or_closeout_receipt.v1",
        **base,
        "verdict": FINAL_VERDICT,
        "court_complete": True,
        "candidate_revision_allowed_next": True,
        "candidate_v2_generation_performed": False,
        "shadow_screen_execution_performed": False,
        "r6_remains_closed": True,
        "input_universe_for_next_counted_screen_must_be_new_or_blinded": True,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    next_lawful_move_receipt = {
        "schema_id": "kt.operator.b04_r6_candidate_revision_next_lawful_move_receipt.v1",
        **base,
        "verdict": FINAL_VERDICT,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    outputs: Dict[str, Any] = {
        OUTPUTS["authority_packet"]: authority_packet,
        OUTPUTS["authority_receipt"]: authority_receipt,
        OUTPUTS["failure_autopsy_packet"]: failure_autopsy_packet,
        OUTPUTS["failure_autopsy_receipt"]: failure_autopsy_receipt,
        OUTPUTS["per_row_failure_matrix"]: per_row_failure_matrix,
        OUTPUTS["candidate_static_delta_matrix"]: candidate_static_delta_matrix,
        OUTPUTS["revision_eligibility_packet"]: revision_eligibility_packet,
        OUTPUTS["revision_eligibility_receipt"]: revision_eligibility_receipt,
        OUTPUTS["revision_blocker_ledger"]: revision_blocker_ledger,
        OUTPUTS["next_screen_input_policy_packet"]: next_screen_input_policy_packet,
        OUTPUTS["blind_input_requirement_receipt"]: blind_input_requirement_receipt,
        OUTPUTS["next_lawful_move_receipt"]: next_lawful_move_receipt,
        OUTPUTS["report_md"]: _report(FINAL_VERDICT, diagnostics),
    }
    for filename, payload in outputs.items():
        path = reports_root / filename
        if isinstance(payload, str):
            path.write_text(payload, encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, payload)
    return {
        "verdict": FINAL_VERDICT,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "live_blocker_count": revision_blocker_ledger["live_blocker_count"],
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Author the B04 R6 candidate revision-or-closeout court.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(reports_root=common.resolve_path(root, args.reports_root))
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
