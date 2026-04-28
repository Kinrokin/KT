from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-second-shadow-forensic-rerun-bar"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_SECOND_SHADOW_SCREEN_FORENSIC_AND_RERUN_BAR"
PREVIOUS_LANE = "B04_R6_SECOND_SHADOW_ROUTER_SUPERIORITY_SCREEN"

PRIOR_VERDICT = "R6_SECOND_SHADOW_SCREEN_INVALIDATED__DISQUALIFIER_TRIGGERED"
EXPECTED_PRIOR_NEXT_MOVE = "AUTHOR_B04_R6_SECOND_SHADOW_SCREEN_FORENSIC_AND_RERUN_BAR_PACKET"

VERDICT_CANDIDATE_DISQUALIFIED = "R6_SECOND_SHADOW_INVALIDATION_CONFIRMED__CANDIDATE_V2_DISQUALIFIED"
VERDICT_HARNESS_DEFECT = "R6_SECOND_SHADOW_INVALIDATION_HARNESS_DEFECT__RERUN_REVIEW_AUTHORIZED"
VERDICT_CONTRACT_DEFECT = "R6_SECOND_SHADOW_INVALIDATION_CONTRACT_DEFECT__CONTRACT_REPAIR_REQUIRED"
VERDICT_INPUT_DEFECT = "R6_SECOND_SHADOW_INVALIDATION_INPUT_DEFECT__NEW_INPUT_UNIVERSE_REQUIRED"
VERDICT_MIXED_DEFECT = "R6_SECOND_SHADOW_INVALIDATION_MIXED_DEFECT__FORENSIC_REMEDIATION_REQUIRED"

NEXT_CANDIDATE_DISQUALIFIED = "AUTHOR_B04_R6_CANDIDATE_V2_DISQUALIFICATION_AND_CLOSEOUT_OR_MAJOR_REDESIGN_PACKET"
NEXT_HARNESS_DEFECT = "AUTHOR_B04_R6_SECOND_SHADOW_HARNESS_REPAIR_AND_RERUN_REVIEW_PACKET"
NEXT_CONTRACT_DEFECT = "AUTHOR_B04_R6_SECOND_SHADOW_CONTRACT_REPAIR_PACKET"
NEXT_INPUT_DEFECT = "AUTHOR_B04_R6_NEW_BLIND_INPUT_UNIVERSE_PACKET"
NEXT_MIXED_DEFECT = "AUTHOR_B04_R6_FORENSIC_REMEDIATION_PACKET"

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
    "result_packet": "KT_PROD_CLEANROOM/reports/b04_r6_second_shadow_screen_result_packet.json",
    "result_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_second_shadow_screen_result_receipt.json",
    "scorecard": "KT_PROD_CLEANROOM/reports/b04_r6_second_shadow_scorecard.json",
    "route_trace": "KT_PROD_CLEANROOM/reports/b04_r6_second_shadow_route_trace_matrix.json",
    "abstention_overrouting": "KT_PROD_CLEANROOM/reports/b04_r6_second_shadow_abstention_overrouting_matrix.json",
    "mirror_masked_invariance": "KT_PROD_CLEANROOM/reports/b04_r6_second_shadow_mirror_masked_invariance_matrix.json",
    "disqualifier_ledger": "KT_PROD_CLEANROOM/reports/b04_r6_second_shadow_disqualifier_ledger.json",
    "screen_execution_packet": "KT_PROD_CLEANROOM/reports/b04_r6_second_shadow_screen_execution_packet.json",
    "screen_execution_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_second_shadow_screen_execution_receipt.json",
    "screen_disqualifier_contract": "KT_PROD_CLEANROOM/reports/b04_r6_second_shadow_screen_disqualifier_contract.json",
    "candidate_v2_admissibility": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v2_admissibility_receipt.json",
    "candidate_v2_manifest": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v2_manifest.json",
    "blind_contract": "KT_PROD_CLEANROOM/reports/b04_r6_new_blind_input_universe_contract.json",
    "metric_contract": "KT_PROD_CLEANROOM/reports/b04_r6_metric_thresholds_contract.json",
    "static_baseline_guard": "KT_PROD_CLEANROOM/reports/b04_r6_static_baseline_immutability_guard_receipt.json",
}

OUTPUTS = {
    "forensic_packet": "b04_r6_second_shadow_screen_forensic_packet.json",
    "forensic_receipt": "b04_r6_second_shadow_screen_forensic_receipt.json",
    "disqualifier_autopsy": "b04_r6_second_shadow_screen_disqualifier_autopsy.json",
    "guard_failure_matrix": "b04_r6_candidate_v2_guard_failure_matrix.json",
    "overrouting_autopsy": "b04_r6_candidate_v2_overrouting_autopsy.json",
    "abstention_autopsy": "b04_r6_candidate_v2_abstention_collapse_autopsy.json",
    "control_autopsy": "b04_r6_candidate_v2_control_degradation_autopsy.json",
    "rerun_bar_packet": "b04_r6_second_shadow_screen_rerun_bar_packet.json",
    "rerun_bar_receipt": "b04_r6_second_shadow_screen_rerun_bar_receipt.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
    "candidate_family_autopsy": "b04_r6_candidate_family_autopsy_prep.json",
    "static_dominance_prep": "b04_r6_static_comparator_dominance_prep.json",
    "router_architecture_alternatives": "b04_r6_router_architecture_alternatives_prep.json",
    "closeout_draft": "b04_r6_closeout_or_major_redesign_draft.json",
    "candidate_v3_requirements_draft": "b04_r6_candidate_v3_requirements_draft.json",
    "external_routing_research_map": "b04_r6_external_routing_research_map_prep.json",
    "report_md": "COHORT0_B04_R6_SECOND_SHADOW_FORENSIC_RERUN_BAR_REPORT.md",
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


def _base(*, generated_utc: str, head: str, subject_main_head: str, status: str = "PASS") -> Dict[str, Any]:
    return {
        "status": status,
        "generated_utc": generated_utc,
        "current_git_head": head,
        "subject_main_head": subject_main_head,
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
            raise RuntimeError(f"FAIL_CLOSED: missing forensic input {raw}")
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    return rows


def _rows(payload: Dict[str, Any], *, label: str) -> list[Dict[str, Any]]:
    rows = payload.get("rows", payload.get("entries", payload.get("candidate_rows")))
    if not isinstance(rows, list):
        raise RuntimeError(f"FAIL_CLOSED: {label} missing rows/entries list")
    out: list[Dict[str, Any]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise RuntimeError(f"FAIL_CLOSED: {label} row {index} must be an object")
        out.append(dict(row))
    return out


def _require_prior_state(payloads: Dict[str, Dict[str, Any]]) -> None:
    for label, payload in payloads.items():
        _ensure_boundaries(payload, label=label)
    result = payloads["result_receipt"]
    scorecard = payloads["scorecard"]
    if result.get("verdict") != PRIOR_VERDICT:
        raise RuntimeError("FAIL_CLOSED: forensic court requires second shadow invalidation verdict")
    if result.get("next_lawful_move") != EXPECTED_PRIOR_NEXT_MOVE:
        raise RuntimeError("FAIL_CLOSED: second shadow result must point to forensic rerun-bar packet")
    if result.get("candidate_win_count") != 0 or result.get("case_count") != 6:
        raise RuntimeError("FAIL_CLOSED: forensic court expects 0/6 second-screen result")
    if result.get("disqualifier_count") != 3:
        raise RuntimeError("FAIL_CLOSED: forensic court expects three triggered disqualifiers")
    if scorecard.get("screen_verdict") != PRIOR_VERDICT:
        raise RuntimeError("FAIL_CLOSED: scorecard verdict mismatch")
    if payloads["candidate_v2_admissibility"].get("candidate_v2_admissible") is not True:
        raise RuntimeError("FAIL_CLOSED: candidate v2 must have been admissible before invalidation")
    if payloads["blind_contract"].get("row_count") != 6:
        raise RuntimeError("FAIL_CLOSED: blind input universe must remain six rows")
    if payloads["static_baseline_guard"].get("static_baseline_mutated") is not False:
        raise RuntimeError("FAIL_CLOSED: static baseline guard reports mutation")


def _contract_ids(payload: Dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for row in payload.get("hard_disqualifiers", []):
        if isinstance(row, dict) and row.get("id"):
            ids.add(str(row["id"]))
    return ids


def _classify(payloads: Dict[str, Dict[str, Any]]) -> tuple[str, str, str]:
    route_rows = _rows(payloads["route_trace"], label="route trace")
    abstention_rows = _rows(payloads["abstention_overrouting"], label="abstention/overrouting matrix")
    disqualifiers = _rows(payloads["disqualifier_ledger"], label="disqualifier ledger")
    contract_ids = _contract_ids(payloads["screen_disqualifier_contract"])
    triggered_ids = {str(row.get("disqualifier_id", "")) for row in disqualifiers}
    required_ids = {"CONTROL_DEGRADATION", "ABSTENTION_COLLAPSE", "OVERRouting_COLLAPSE"}
    if not required_ids.issubset(triggered_ids):
        return ("MIXED_DEFECT", VERDICT_MIXED_DEFECT, NEXT_MIXED_DEFECT)
    if not required_ids.issubset(contract_ids):
        return ("METRIC_OR_DISQUALIFIER_CONTRACT_DEFECT", VERDICT_CONTRACT_DEFECT, NEXT_CONTRACT_DEFECT)
    overroute_rows = [
        row for row in abstention_rows
        if row.get("fallback_expected") is True and row.get("candidate_abstained") is False and row.get("overrouting_detected") is True
    ]
    degradation_rows = [
        row for row in route_rows
        if row.get("static_fallback_expected") is True and row.get("candidate_abstained") is False and float(row.get("route_quality_delta", 0)) < 0
    ]
    if overroute_rows and degradation_rows:
        return ("CANDIDATE_BEHAVIOR_DEFECT", VERDICT_CANDIDATE_DISQUALIFIED, NEXT_CANDIDATE_DISQUALIFIED)
    return ("MIXED_DEFECT", VERDICT_MIXED_DEFECT, NEXT_MIXED_DEFECT)


def _row_by_case(rows: list[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {str(row.get("case_id", "")): dict(row) for row in rows if row.get("case_id")}


def _make_autopsies(payloads: Dict[str, Dict[str, Any]], cause_class: str) -> Dict[str, Any]:
    route_rows = _rows(payloads["route_trace"], label="route trace")
    abstention_rows = _rows(payloads["abstention_overrouting"], label="abstention/overrouting matrix")
    disqualifier_rows = _rows(payloads["disqualifier_ledger"], label="disqualifier ledger")
    route_by_case = _row_by_case(route_rows)
    abstention_by_case = _row_by_case(abstention_rows)
    implicated_cases = sorted(
        {
            row["case_id"]
            for row in route_rows
            if row.get("static_fallback_expected") is True and row.get("candidate_abstained") is False
        }
        | {
            row["case_id"]
            for row in abstention_rows
            if row.get("fallback_expected") is True and row.get("candidate_abstained") is False
        }
    )
    guard_rows: list[Dict[str, Any]] = []
    for case_id in sorted(route_by_case):
        route = route_by_case[case_id]
        abstention = abstention_by_case.get(case_id, {})
        guard_rows.append(
            {
                "case_id": case_id,
                "family": route.get("family"),
                "control_degradation": float(route.get("route_quality_delta", 0)) < 0,
                "abstention_collapse": abstention.get("static_hold_preserved") is False,
                "overrouting_collapse": abstention.get("overrouting_detected") is True,
                "candidate_abstained": route.get("candidate_abstained"),
                "static_fallback_expected": route.get("static_fallback_expected"),
                "candidate_adapter_ids": route.get("candidate_adapter_ids"),
                "static_adapter_ids": route.get("static_adapter_ids"),
                "cause_class": cause_class if case_id in implicated_cases else "NOT_IMPLICATED",
            }
        )
    return {
        "disqualifier_rows": disqualifier_rows,
        "guard_rows": guard_rows,
        "implicated_cases": implicated_cases,
        "overrouting_rows": [row for row in guard_rows if row["overrouting_collapse"]],
        "abstention_rows": [row for row in guard_rows if row["abstention_collapse"]],
        "control_rows": [row for row in guard_rows if row["control_degradation"]],
    }


def _prep(base: Dict[str, Any], *, schema_id: str, purpose: str, next_lawful_move: str) -> Dict[str, Any]:
    return {
        "schema_id": schema_id,
        **base,
        "lane_type": "PREP_ONLY",
        "purpose": purpose,
        "may_change_live_truth": False,
        "next_lawful_move": next_lawful_move,
    }


def _write_report(verdict: str, cause_class: str, implicated_cases: list[str], next_move: str) -> str:
    return (
        "# Cohort-0 B04 R6 Second Shadow Forensic And Rerun Bar\n\n"
        f"Verdict: `{verdict}`\n\n"
        f"Cause class: `{cause_class}`\n\n"
        f"Implicated cases: `{', '.join(implicated_cases) if implicated_cases else 'none'}`\n\n"
        "The second shadow screen remains invalidated. This packet does not open R6, does not earn learned-router "
        "superiority, does not authorize activation review, and does not permit casual rerun.\n\n"
        f"Next lawful move: `{next_move}`\n"
    )


def run(*, reports_root: Path) -> Dict[str, Any]:
    root = repo_root()
    current_branch = common.git_current_branch_name(root)
    if current_branch not in ALLOWED_BRANCHES:
        allowed = ", ".join(sorted(ALLOWED_BRANCHES))
        raise RuntimeError(f"FAIL_CLOSED: must run on one of: {allowed}")
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 forensic rerun-bar freeze")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    payloads = {role: _load(root, raw, label=role) for role, raw in INPUTS.items()}
    _require_prior_state(payloads)
    trust_validation = validate_trust_zones(root=root)
    common.ensure_pass(trust_validation, label="trust-zone validation")
    if trust_validation.get("failures"):
        raise RuntimeError("FAIL_CLOSED: trust-zone validation must have zero failures")

    cause_class, verdict, next_move = _classify(payloads)
    autopsies = _make_autopsies(payloads, cause_class)
    rerun_allowed = verdict == VERDICT_HARNESS_DEFECT
    generated_utc = utc_now_iso_z()
    head = common.git_rev_parse(root, "HEAD")
    base = _base(generated_utc=generated_utc, head=head, subject_main_head=head)
    input_bindings = _input_hashes(root)

    forensic_packet = {
        "schema_id": "kt.operator.b04_r6_second_shadow_screen_forensic_packet.v1",
        **base,
        "forensic_question": "Was invalidation caused by candidate behavior, harness defect, metric/contract defect, input defect, or mixed defect?",
        "allowed_outcomes": [
            VERDICT_CANDIDATE_DISQUALIFIED,
            VERDICT_HARNESS_DEFECT,
            VERDICT_CONTRACT_DEFECT,
            VERDICT_INPUT_DEFECT,
            VERDICT_MIXED_DEFECT,
        ],
        "input_bindings": input_bindings,
        "prior_verdict": PRIOR_VERDICT,
        "cause_class": cause_class,
        "verdict": verdict,
        "next_lawful_move": next_move,
    }
    forensic_receipt = {
        "schema_id": "kt.operator.b04_r6_second_shadow_screen_forensic_receipt.v1",
        **base,
        "verdict": verdict,
        "cause_class": cause_class,
        "candidate_v2_disqualified_for_current_r6_screen_law": verdict == VERDICT_CANDIDATE_DISQUALIFIED,
        "activation_review_authorized": False,
        "rerun_review_authorized": rerun_allowed,
        "next_lawful_move": next_move,
    }
    disqualifier_autopsy = {
        "schema_id": "kt.operator.b04_r6_second_shadow_screen_disqualifier_autopsy.v1",
        **base,
        "cause_class": cause_class,
        "entries": autopsies["disqualifier_rows"],
        "triggered_count": len(autopsies["disqualifier_rows"]),
        "implicated_cases": autopsies["implicated_cases"],
        "next_lawful_move": next_move,
    }
    guard_failure_matrix = {
        "schema_id": "kt.operator.b04_r6_candidate_v2_guard_failure_matrix.v1",
        **base,
        "rows": autopsies["guard_rows"],
        "cause_class": cause_class,
        "next_lawful_move": next_move,
    }
    overrouting_autopsy = {
        "schema_id": "kt.operator.b04_r6_candidate_v2_overrouting_autopsy.v1",
        **base,
        "rows": autopsies["overrouting_rows"],
        "cause_class": cause_class,
        "interpretation": "Candidate routed when static fallback/abstention should dominate.",
        "next_lawful_move": next_move,
    }
    abstention_autopsy = {
        "schema_id": "kt.operator.b04_r6_candidate_v2_abstention_collapse_autopsy.v1",
        **base,
        "rows": autopsies["abstention_rows"],
        "cause_class": cause_class,
        "interpretation": "Candidate failed the static-hold abstention guard on implicated row(s).",
        "next_lawful_move": next_move,
    }
    control_autopsy = {
        "schema_id": "kt.operator.b04_r6_candidate_v2_control_degradation_autopsy.v1",
        **base,
        "rows": autopsies["control_rows"],
        "cause_class": cause_class,
        "interpretation": "Candidate produced worse-than-static route quality on protected control row(s).",
        "next_lawful_move": next_move,
    }
    rerun_bar_packet = {
        "schema_id": "kt.operator.b04_r6_second_shadow_screen_rerun_bar_packet.v1",
        **base,
        "status": "FROZEN_PACKET",
        "default_rerun_bar": True,
        "rerun_allowed": rerun_allowed,
        "rerun_release_rule": "Rerun may be reviewed only if a later forensic court proves harness, contract, or input defect; candidate-behavior invalidation bars casual rerun.",
        "six_row_blind_universe_reuse_as_fresh_proof_allowed": False,
        "screen_result_may_be_used_as_diagnostic_evidence": True,
        "candidate_v2_activation_review_allowed": False,
        "next_lawful_move": next_move,
    }
    rerun_bar_receipt = {
        "schema_id": "kt.operator.b04_r6_second_shadow_screen_rerun_bar_receipt.v1",
        **base,
        "verdict": verdict,
        "cause_class": cause_class,
        "rerun_allowed": rerun_allowed,
        "rerun_bar_active": not rerun_allowed,
        "candidate_v2_disqualified": verdict == VERDICT_CANDIDATE_DISQUALIFIED,
        "next_lawful_move": next_move,
    }
    next_receipt = {
        "schema_id": "kt.operator.b04_r6_next_lawful_move_receipt.v1",
        **base,
        "verdict": verdict,
        "cause_class": cause_class,
        "next_lawful_move": next_move,
    }
    prep_base = {**base, "verdict": verdict, "cause_class": cause_class}
    outputs: Dict[str, Any] = {
        OUTPUTS["forensic_packet"]: forensic_packet,
        OUTPUTS["forensic_receipt"]: forensic_receipt,
        OUTPUTS["disqualifier_autopsy"]: disqualifier_autopsy,
        OUTPUTS["guard_failure_matrix"]: guard_failure_matrix,
        OUTPUTS["overrouting_autopsy"]: overrouting_autopsy,
        OUTPUTS["abstention_autopsy"]: abstention_autopsy,
        OUTPUTS["control_autopsy"]: control_autopsy,
        OUTPUTS["rerun_bar_packet"]: rerun_bar_packet,
        OUTPUTS["rerun_bar_receipt"]: rerun_bar_receipt,
        OUTPUTS["next_lawful_move"]: next_receipt,
        OUTPUTS["candidate_family_autopsy"]: _prep(prep_base, schema_id="kt.operator.b04_r6_candidate_family_autopsy_prep.v1", purpose="Compare v1/v2 failure patterns before any candidate-v3 scope.", next_lawful_move=next_move),
        OUTPUTS["static_dominance_prep"]: _prep(prep_base, schema_id="kt.operator.b04_r6_static_comparator_dominance_prep.v1", purpose="Prepare static comparator dominance analysis without weakening comparator.", next_lawful_move=next_move),
        OUTPUTS["router_architecture_alternatives"]: _prep(prep_base, schema_id="kt.operator.b04_r6_router_architecture_alternatives_prep.v1", purpose="Inventory abstention-first, calibrated, threshold, cost-aware, and hybrid router options as prep only.", next_lawful_move=next_move),
        OUTPUTS["closeout_draft"]: _prep(prep_base, schema_id="kt.operator.b04_r6_closeout_or_major_redesign_draft.v1", purpose="Prepare honest closeout or major-redesign decision court.", next_lawful_move=next_move),
        OUTPUTS["candidate_v3_requirements_draft"]: _prep(prep_base, schema_id="kt.operator.b04_r6_candidate_v3_requirements_draft.v1", purpose="Draft candidate-v3 requirements only; no generation and new blind universe required if pursued.", next_lawful_move=next_move),
        OUTPUTS["external_routing_research_map"]: _prep(prep_base, schema_id="kt.operator.b04_r6_external_routing_research_map_prep.v1", purpose="Map external selector/calibration/router ideas into KT-native source law without authority claims.", next_lawful_move=next_move),
        OUTPUTS["report_md"]: _write_report(verdict, cause_class, autopsies["implicated_cases"], next_move),
    }
    for filename, payload in outputs.items():
        path = reports_root / filename
        if isinstance(payload, str):
            path.write_text(payload, encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, payload)
    return {"verdict": verdict, "cause_class": cause_class, "rerun_allowed": rerun_allowed, "next_lawful_move": next_move}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Freeze B04 R6 second-shadow forensic and rerun bar.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(reports_root=common.resolve_path(root, args.reports_root))
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
