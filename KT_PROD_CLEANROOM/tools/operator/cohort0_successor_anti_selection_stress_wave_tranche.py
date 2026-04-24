from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_dual_lane_first_execution_tranche as dual_lane
from tools.operator import cohort0_first_successor_evidence_setup_tranche as setup_tranche
from tools.operator import cohort0_successor_gate_d_narrow_admissibility_review_tranche as narrow_review
from tools.operator import cohort0_third_successor_bridge_bound_tranche as third_wave
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_VERDICT_PACKET_REL = setup_tranche.DEFAULT_VERDICT_PACKET_REL
DEFAULT_REENTRY_BLOCK_REL = setup_tranche.DEFAULT_REENTRY_BLOCK_REL
DEFAULT_LANE_A_DUAL_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{dual_lane.OUTPUT_LANE_A_SCORECARD}"
DEFAULT_LANE_B_DUAL_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{dual_lane.OUTPUT_LANE_B_SCORECARD}"
DEFAULT_THIRD_ROW_PANEL_REL = f"KT_PROD_CLEANROOM/reports/{third_wave.OUTPUT_ROW_PANEL}"
DEFAULT_LANE_B_RESERVE_SCORECARD_REL = "KT_PROD_CLEANROOM/reports/cohort0_lane_b_reserve_challenge_scorecard.json"
DEFAULT_NARROW_REVIEW_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{narrow_review.OUTPUT_RECEIPT}"
DEFAULT_REPORTS_ROOT_REL = setup_tranche.DEFAULT_REPORTS_ROOT_REL

OUTPUT_PACKET = "cohort0_successor_anti_selection_stress_wave_packet.json"
OUTPUT_RECEIPT = "cohort0_successor_anti_selection_stress_wave_receipt.json"
OUTPUT_REPORT = "COHORT0_SUCCESSOR_ANTI_SELECTION_STRESS_WAVE_REPORT.md"

EXECUTION_STATUS = "PASS__SUCCESSOR_ANTI_SELECTION_STRESS_WAVE_EXECUTED"
BOUNDED_DEFECT_ID = "FAMILY_SIDE_NON_PROMOTED_DEPTH_EXHAUSTED_AFTER_RESERVE"


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise RuntimeError(f"FAIL_CLOSED: {label} must be a JSON object: {path.as_posix()}")
    return payload


def _ensure_pass(payload: Dict[str, Any], *, label: str) -> None:
    if str(payload.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: {label} must have status PASS")


def _require_same_subject_head(packets: Sequence[Dict[str, Any]]) -> str:
    heads = {
        str(packet.get("subject_head", "")).strip()
        for packet in packets
        if isinstance(packet, dict) and str(packet.get("subject_head", "")).strip()
    }
    if len(heads) != 1:
        raise RuntimeError("FAIL_CLOSED: anti-selection wave requires one same-head authority line")
    return next(iter(heads))


def _round_float(value: Any, digits: int = 6) -> float:
    return round(float(value), digits)


def _bool_rate(flags: Sequence[bool]) -> float:
    if not flags:
        return 0.0
    return _round_float(sum(1 for item in flags if item) / len(flags))


def _validate_inputs(
    *,
    verdict_packet: Dict[str, Any],
    reentry_block: Dict[str, Any],
    lane_a_dual_scorecard: Dict[str, Any],
    lane_b_dual_scorecard: Dict[str, Any],
    third_row_panel: Dict[str, Any],
    lane_b_reserve_scorecard: Dict[str, Any],
    narrow_review_receipt: Dict[str, Any],
) -> None:
    for payload, label in (
        (verdict_packet, "hardened ceiling verdict packet"),
        (reentry_block, "gate d reentry block contract"),
        (lane_a_dual_scorecard, "dual-lane lane a scorecard"),
        (lane_b_dual_scorecard, "dual-lane lane b scorecard"),
        (third_row_panel, "third successor row panel"),
        (lane_b_reserve_scorecard, "lane b reserve challenge scorecard"),
        (narrow_review_receipt, "narrow review receipt"),
    ):
        _ensure_pass(payload, label=label)

    if str(verdict_packet.get("final_verdict_id", "")).strip() != setup_tranche.EXPECTED_FINAL_VERDICT_ID:
        raise RuntimeError("FAIL_CLOSED: verdict packet final verdict mismatch")
    if not bool(verdict_packet.get("current_lane_closed", False)):
        raise RuntimeError("FAIL_CLOSED: current same-head lane must remain closed")
    if bool(verdict_packet.get("same_head_counted_reentry_admissible_now", True)):
        raise RuntimeError("FAIL_CLOSED: same-head counted reentry must remain blocked")
    if str(reentry_block.get("reentry_status", "")).strip() != "BLOCKED__CURRENT_LANE_HARDENED_CEILING":
        raise RuntimeError("FAIL_CLOSED: reentry block must remain active")

    if str(lane_a_dual_scorecard.get("execution_status", "")).strip() != "PASS__LANE_A_FIRST_CONCURRENT_SCORING_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: dual-lane Lane A scorecard must exist")
    if str(lane_b_dual_scorecard.get("execution_status", "")).strip() != "PASS__LANE_B_FIRST_CONCURRENT_SCREENING_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: dual-lane Lane B scorecard must exist")
    if str(lane_b_reserve_scorecard.get("execution_status", "")).strip() != "PASS__LANE_B_RESERVE_CHALLENGE_SCORED":
        raise RuntimeError("FAIL_CLOSED: Lane B reserve challenge must exist")
    if str(narrow_review_receipt.get("execution_status", "")).strip() != "PASS__SUCCESSOR_GATE_D_NARROW_ADMISSIBILITY_REVIEW_CONVENED":
        raise RuntimeError("FAIL_CLOSED: narrow review must exist before anti-selection wave")
    if not bool(narrow_review_receipt.get("narrow_successor_gate_d_admissibility_confirmed", False)):
        raise RuntimeError("FAIL_CLOSED: narrow admissibility must remain confirmed")


def _rows_by_case(third_row_panel: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {
        str(row.get("case_id", "")).strip(): row
        for row in third_row_panel.get("rows", [])
        if isinstance(row, dict) and str(row.get("case_id", "")).strip()
    }


def _pick_lane_a_non_promoted_mutations(lane_a_dual_scorecard: Dict[str, Any]) -> List[Dict[str, Any]]:
    preferred_ids = [
        "MUTATION::AUDITOR_ADMISSIBILITY_FAIL_CLOSED__REPAIR_ORDER_COLLISION",
        "MUTATION::STRATEGIST_CONSEQUENCE_CHAIN__DEFERRED_ROLLBACK_CASCADE",
    ]
    candidates = [
        item for item in lane_a_dual_scorecard.get("candidates", [])
        if isinstance(item, dict)
    ]
    by_id = {str(item.get("mutation_candidate_id", "")).strip(): item for item in candidates}
    selected: List[Dict[str, Any]] = []
    for item_id in preferred_ids:
        if item_id in by_id:
            selected.append(dict(by_id[item_id]))
    if len(selected) < 2:
        reserves = {
            str(item.get("item_id", "")).strip()
            for item in lane_a_dual_scorecard.get("reserves", [])
            if isinstance(item, dict)
        }
        fallback = [
            dict(item)
            for item in candidates
            if str(item.get("mutation_candidate_id", "")).strip() in reserves
            and str(item.get("variant_type", "")).strip() == "core"
        ]
        for item in fallback:
            item_id = str(item.get("mutation_candidate_id", "")).strip()
            if item_id not in {str(x.get("mutation_candidate_id", "")).strip() for x in selected}:
                selected.append(item)
            if len(selected) == 2:
                break
    if len(selected) < 2:
        raise RuntimeError("FAIL_CLOSED: unable to select two non-promoted Lane A mutations")
    return selected


def _score_mutation_candidate(candidate: Dict[str, Any], rows_by_case: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    case_id = str(candidate.get("source_case_id", "")).strip()
    primary = dict(rows_by_case.get(case_id, {}))
    masked = dict(rows_by_case.get(f"{case_id}__MASKED", {}))
    if not primary:
        raise RuntimeError(f"FAIL_CLOSED: missing third-wave row for candidate {case_id}")
    rows = [primary]
    if masked:
        rows.append(masked)
    return {
        "mutation_candidate_id": str(candidate.get("mutation_candidate_id", "")).strip(),
        "source_family_id": str(candidate.get("source_family_id", "")).strip(),
        "row_count": len(rows),
        "selected_bridge_reason_exact_accuracy": _bool_rate(
            [bool(row.get("selected_bridge_reason_exact", False)) for row in rows]
        ),
        "selected_bridge_reason_admissible_accuracy": _bool_rate(
            [bool(row.get("selected_bridge_reason_admissible", False)) for row in rows]
        ),
        "total_wrong_route_cost": _round_float(sum(float(row.get("wrong_route_cost", 0.0)) for row in rows)),
        "total_wrong_static_hold_cost": _round_float(sum(float(row.get("wrong_static_hold_cost", 0.0)) for row in rows)),
        "mean_observed_route_margin": _round_float(
            sum(float(row.get("observed_route_margin", 0.0)) for row in rows) / max(1, len(rows))
        ),
    }


def _build_outputs(
    *,
    lane_a_dual_scorecard: Dict[str, Any],
    lane_b_dual_scorecard: Dict[str, Any],
    third_row_panel: Dict[str, Any],
    lane_b_reserve_scorecard: Dict[str, Any],
    subject_head: str,
) -> Dict[str, Dict[str, Any]]:
    selected_mutations = _pick_lane_a_non_promoted_mutations(lane_a_dual_scorecard)
    rows_by_case = _rows_by_case(third_row_panel)
    mutation_scorecards = [_score_mutation_candidate(item, rows_by_case) for item in selected_mutations]
    mutation_side_holds = all(
        item["selected_bridge_reason_exact_accuracy"] >= 1.0
        and item["selected_bridge_reason_admissible_accuracy"] >= 1.0
        and item["total_wrong_route_cost"] > 0.0
        for item in mutation_scorecards
    )

    lane_b_prospects = [
        item for item in lane_b_dual_scorecard.get("prospects", [])
        if isinstance(item, dict)
    ]
    lane_b_survivor_ids = {
        str(item.get("family_id", "")).strip()
        for item in lane_b_dual_scorecard.get("survivors", [])
        if isinstance(item, dict)
    }
    lane_b_reserve_ids = {
        str(item.get("item_id", "")).strip()
        for item in lane_b_dual_scorecard.get("reserves", [])
        if isinstance(item, dict)
    }
    additional_novel_non_promoted_family_ids = [
        str(item.get("family_id", "")).strip()
        for item in lane_b_prospects
        if str(item.get("family_id", "")).strip()
        not in lane_b_survivor_ids | lane_b_reserve_ids
        and bool(item.get("novelty_gate_pass", False))
        and not bool(item.get("legacy_ring_overlap_detected", False))
    ]
    family_side_reserve_hold = (
        float(lane_b_reserve_scorecard.get("all_case_metrics", {}).get("bridge_reason_exact_accuracy", 0.0)) >= 1.0
        and float(lane_b_reserve_scorecard.get("all_case_metrics", {}).get("route_consequence_visible_rate", 0.0)) >= 1.0
    )
    family_side_beyond_reserve_closed = family_side_reserve_hold and len(additional_novel_non_promoted_family_ids) > 0

    overall_closed = mutation_side_holds and family_side_beyond_reserve_closed
    bounded_defects_remaining = [] if overall_closed else [BOUNDED_DEFECT_ID]

    packet = {
        "schema_id": "kt.operator.cohort0_successor_anti_selection_stress_wave_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This wave attacks promotion bias on the successor line. "
            "It does not authorize counted reentry, reopen Gate D, or open Gate E."
        ),
        "execution_status": EXECUTION_STATUS,
        "lane_a_non_promoted_mutation_scorecards": mutation_scorecards,
        "lane_a_mutation_side_holds": mutation_side_holds,
        "lane_b_reserve_family_scorecard_ref": DEFAULT_LANE_B_RESERVE_SCORECARD_REL,
        "lane_b_reserve_family_id": lane_b_reserve_scorecard.get("reserve_item_id", ""),
        "lane_b_reserve_family_holds": family_side_reserve_hold,
        "lane_b_additional_novel_non_promoted_family_ids": additional_novel_non_promoted_family_ids,
        "lane_b_family_side_beyond_reserve_closed": family_side_beyond_reserve_closed,
        "anti_selection_wave_beyond_reserve_executed": True,
        "anti_selection_wave_beyond_reserve_closed": overall_closed,
        "bounded_defects_remaining": bounded_defects_remaining,
        "subject_head": subject_head,
    }

    receipt = {
        "schema_id": "kt.operator.cohort0_successor_anti_selection_stress_wave_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "anti_selection_wave_executed": True,
        "anti_selection_wave_beyond_reserve_executed": True,
        "anti_selection_wave_beyond_reserve_closed": overall_closed,
        "bounded_defects_remaining": bounded_defects_remaining,
        "same_head_counted_reentry_admissible_now": False,
        "gate_d_reopened": False,
        "gate_e_open": False,
        "next_lawful_move": (
            "RECOMPUTE_SUCCESSOR_PREDICATES_AFTER_ANTI_SELECTION_WAVE"
            if overall_closed
            else "ADMIT_OR_DISCOVER_ONE_MORE_NON_PROMOTED_FAMILY_SURFACE_BEFORE_RETRYING_FULL_AUTHORIZATION"
        ),
        "subject_head": subject_head,
    }
    return {"packet": packet, "receipt": receipt}


def _build_report(*, packet: Dict[str, Any], receipt: Dict[str, Any]) -> str:
    mutation_lines = "\n".join(
        f"- `{item.get('mutation_candidate_id', '')}` exact `{item.get('selected_bridge_reason_exact_accuracy', 0.0)}` route-cost `{item.get('total_wrong_route_cost', 0.0)}`"
        for item in packet.get("lane_a_non_promoted_mutation_scorecards", [])
    )
    return (
        "# Cohort0 Successor Anti-Selection Stress Wave Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Anti-selection wave executed: `{receipt.get('anti_selection_wave_executed', False)}`\n"
        f"- Anti-selection closed beyond reserve: `{receipt.get('anti_selection_wave_beyond_reserve_closed', False)}`\n"
        f"- Counted reentry admissible now: `{receipt.get('same_head_counted_reentry_admissible_now', False)}`\n"
        f"- Gate D reopened: `{receipt.get('gate_d_reopened', False)}`\n"
        f"- Gate E open: `{receipt.get('gate_e_open', False)}`\n"
        f"- Next lawful move: `{receipt.get('next_lawful_move', '')}`\n\n"
        "## Lane A Non-Promoted Mutation Side\n"
        f"{mutation_lines}\n\n"
        "## Lane B Family Side\n"
        f"- Reserve family id: `{packet.get('lane_b_reserve_family_id', '')}`\n"
        f"- Reserve family holds: `{packet.get('lane_b_reserve_family_holds', False)}`\n"
        f"- Additional novel non-promoted family ids: `{packet.get('lane_b_additional_novel_non_promoted_family_ids', [])}`\n"
        f"- Bounded defects remaining: `{packet.get('bounded_defects_remaining', [])}`\n"
    )


def run(
    *,
    verdict_packet_path: Path,
    reentry_block_path: Path,
    lane_a_dual_scorecard_path: Path,
    lane_b_dual_scorecard_path: Path,
    third_row_panel_path: Path,
    lane_b_reserve_scorecard_path: Path,
    narrow_review_receipt_path: Path,
    reports_root: Path,
) -> Dict[str, Any]:
    verdict_packet = _load_json_required(verdict_packet_path, label="hardened ceiling verdict packet")
    reentry_block = _load_json_required(reentry_block_path, label="gate d reentry block contract")
    lane_a_dual_scorecard = _load_json_required(lane_a_dual_scorecard_path, label="dual-lane lane a scorecard")
    lane_b_dual_scorecard = _load_json_required(lane_b_dual_scorecard_path, label="dual-lane lane b scorecard")
    third_row_panel = _load_json_required(third_row_panel_path, label="third row panel")
    lane_b_reserve_scorecard = _load_json_required(lane_b_reserve_scorecard_path, label="lane b reserve scorecard")
    narrow_review_receipt = _load_json_required(narrow_review_receipt_path, label="narrow review receipt")

    _validate_inputs(
        verdict_packet=verdict_packet,
        reentry_block=reentry_block,
        lane_a_dual_scorecard=lane_a_dual_scorecard,
        lane_b_dual_scorecard=lane_b_dual_scorecard,
        third_row_panel=third_row_panel,
        lane_b_reserve_scorecard=lane_b_reserve_scorecard,
        narrow_review_receipt=narrow_review_receipt,
    )
    subject_head = _require_same_subject_head(
        (
            verdict_packet,
            reentry_block,
            lane_a_dual_scorecard,
            lane_b_dual_scorecard,
            third_row_panel,
            lane_b_reserve_scorecard,
            narrow_review_receipt,
        )
    )

    outputs = _build_outputs(
        lane_a_dual_scorecard=lane_a_dual_scorecard,
        lane_b_dual_scorecard=lane_b_dual_scorecard,
        third_row_panel=third_row_panel,
        lane_b_reserve_scorecard=lane_b_reserve_scorecard,
        subject_head=subject_head,
    )

    reports_root.mkdir(parents=True, exist_ok=True)
    packet_path = reports_root / OUTPUT_PACKET
    receipt_path = reports_root / OUTPUT_RECEIPT
    report_path = reports_root / OUTPUT_REPORT
    write_json_stable(packet_path, outputs["packet"])
    write_json_stable(receipt_path, outputs["receipt"])
    _write_text(report_path, _build_report(packet=outputs["packet"], receipt=outputs["receipt"]))

    return {
        "status": "PASS",
        "execution_status": EXECUTION_STATUS,
        "anti_selection_wave_beyond_reserve_closed": outputs["receipt"]["anti_selection_wave_beyond_reserve_closed"],
        "output_count": 3,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Stress the successor line against anti-selection concerns beyond promoted survivors."
    )
    parser.add_argument("--verdict-packet", default=DEFAULT_VERDICT_PACKET_REL)
    parser.add_argument("--reentry-block", default=DEFAULT_REENTRY_BLOCK_REL)
    parser.add_argument("--lane-a-dual-scorecard", default=DEFAULT_LANE_A_DUAL_SCORECARD_REL)
    parser.add_argument("--lane-b-dual-scorecard", default=DEFAULT_LANE_B_DUAL_SCORECARD_REL)
    parser.add_argument("--third-row-panel", default=DEFAULT_THIRD_ROW_PANEL_REL)
    parser.add_argument("--lane-b-reserve-scorecard", default=DEFAULT_LANE_B_RESERVE_SCORECARD_REL)
    parser.add_argument("--narrow-review-receipt", default=DEFAULT_NARROW_REVIEW_RECEIPT_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    args = parser.parse_args(argv)

    root = repo_root()
    result = run(
        verdict_packet_path=_resolve(root, args.verdict_packet),
        reentry_block_path=_resolve(root, args.reentry_block),
        lane_a_dual_scorecard_path=_resolve(root, args.lane_a_dual_scorecard),
        lane_b_dual_scorecard_path=_resolve(root, args.lane_b_dual_scorecard),
        third_row_panel_path=_resolve(root, args.third_row_panel),
        lane_b_reserve_scorecard_path=_resolve(root, args.lane_b_reserve_scorecard),
        narrow_review_receipt_path=_resolve(root, args.narrow_review_receipt),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in (
        "status",
        "execution_status",
        "anti_selection_wave_beyond_reserve_closed",
        "output_count",
        "receipt_path",
        "subject_head",
    ):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
