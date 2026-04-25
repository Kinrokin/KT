from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_dual_lane_first_execution_tranche as dual_lane
from tools.operator import cohort0_first_successor_evidence_setup_tranche as setup_tranche
from tools.operator import cohort0_lane_b_family_level_bridge_harness_tranche as lane_b_exec
from tools.operator import cohort0_successor_gate_d_narrow_admissibility_review_tranche as narrow_review
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_VERDICT_PACKET_REL = setup_tranche.DEFAULT_VERDICT_PACKET_REL
DEFAULT_REENTRY_BLOCK_REL = setup_tranche.DEFAULT_REENTRY_BLOCK_REL
DEFAULT_LANE_B_DUAL_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{dual_lane.OUTPUT_LANE_B_SCORECARD}"
DEFAULT_LANE_B_RESERVE_SCORECARD_REL = "KT_PROD_CLEANROOM/reports/cohort0_lane_b_reserve_challenge_scorecard.json"
DEFAULT_LANE_B_FAMILY_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{lane_b_exec.OUTPUT_SCORECARD}"
DEFAULT_NARROW_REVIEW_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{narrow_review.OUTPUT_RECEIPT}"
DEFAULT_REPORTS_ROOT_REL = setup_tranche.DEFAULT_REPORTS_ROOT_REL

OUTPUT_PACKET = "cohort0_successor_third_surface_breadth_witness_wave_packet.json"
OUTPUT_RECEIPT = "cohort0_successor_third_surface_breadth_witness_wave_receipt.json"
OUTPUT_REPORT = "COHORT0_SUCCESSOR_THIRD_SURFACE_BREADTH_WITNESS_WAVE_REPORT.md"

EXECUTION_STATUS = "PASS__SUCCESSOR_THIRD_SURFACE_BREADTH_WITNESS_WAVE_EXECUTED"


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
        raise RuntimeError("FAIL_CLOSED: third-surface breadth wave requires one same-head authority line")
    return next(iter(heads))


def _validate_inputs(
    *,
    verdict_packet: Dict[str, Any],
    reentry_block: Dict[str, Any],
    lane_b_dual_scorecard: Dict[str, Any],
    lane_b_reserve_scorecard: Dict[str, Any],
    lane_b_family_scorecard: Dict[str, Any],
    narrow_review_receipt: Dict[str, Any],
) -> None:
    for payload, label in (
        (verdict_packet, "hardened ceiling verdict packet"),
        (reentry_block, "gate d reentry block contract"),
        (lane_b_dual_scorecard, "dual-lane lane b scorecard"),
        (lane_b_reserve_scorecard, "lane b reserve challenge scorecard"),
        (lane_b_family_scorecard, "lane b family-level scorecard"),
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

    if str(lane_b_dual_scorecard.get("execution_status", "")).strip() != "PASS__LANE_B_FIRST_CONCURRENT_SCREENING_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: dual-lane Lane B scorecard must exist")
    if str(lane_b_reserve_scorecard.get("execution_status", "")).strip() != "PASS__LANE_B_RESERVE_CHALLENGE_SCORED":
        raise RuntimeError("FAIL_CLOSED: Lane B reserve challenge must exist")
    if str(lane_b_family_scorecard.get("execution_status", "")).strip() != "PASS__LANE_B_FAMILY_LEVEL_BRIDGE_HARNESS_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: Lane B family-level execution must exist")
    if str(narrow_review_receipt.get("execution_status", "")).strip() != "PASS__SUCCESSOR_GATE_D_NARROW_ADMISSIBILITY_REVIEW_CONVENED":
        raise RuntimeError("FAIL_CLOSED: narrow review must exist before third-surface breadth wave")
    if not bool(narrow_review_receipt.get("narrow_successor_gate_d_admissibility_confirmed", False)):
        raise RuntimeError("FAIL_CLOSED: narrow admissibility must remain confirmed")


def _select_reserve_family(lane_b_dual_scorecard: Dict[str, Any]) -> Dict[str, Any]:
    reserve_ids = [
        str(item.get("item_id", "")).strip()
        for item in lane_b_dual_scorecard.get("reserves", [])
        if isinstance(item, dict) and str(item.get("item_id", "")).strip()
    ]
    if not reserve_ids:
        raise RuntimeError("FAIL_CLOSED: no Lane B reserve family available")
    target_id = reserve_ids[0]
    for prospect in lane_b_dual_scorecard.get("prospects", []):
        if isinstance(prospect, dict) and str(prospect.get("family_id", "")).strip() == target_id:
            return dict(prospect)
    raise RuntimeError("FAIL_CLOSED: reserve family missing from Lane B prospects")


def _build_outputs(
    *,
    lane_b_dual_scorecard: Dict[str, Any],
    lane_b_reserve_scorecard: Dict[str, Any],
    lane_b_family_scorecard: Dict[str, Any],
    subject_head: str,
) -> Dict[str, Dict[str, Any]]:
    reserve_family = _select_reserve_family(lane_b_dual_scorecard)
    reserve_family_id = str(reserve_family.get("family_id", "")).strip()
    promoted_family_ids = sorted(
        str(item.get("family_id", "")).strip()
        for item in lane_b_dual_scorecard.get("survivors", [])
        if isinstance(item, dict) and str(item.get("family_id", "")).strip()
    )

    reserve_metrics = dict(lane_b_reserve_scorecard.get("all_case_metrics", {}))
    novelty_gate_pass = bool(reserve_family.get("novelty_gate_pass", False))
    overlap_free = not bool(reserve_family.get("legacy_ring_overlap_detected", False)) and not bool(
        reserve_family.get("current_ring_overlap_detected", False)
    )
    distinct_from_promoted = reserve_family_id not in promoted_family_ids
    reserve_holds = (
        float(reserve_metrics.get("bridge_reason_exact_accuracy", 0.0)) >= 1.0
        and float(reserve_metrics.get("bridge_reason_admissible_accuracy", 0.0)) >= 1.0
        and float(reserve_metrics.get("route_consequence_visible_rate", 0.0)) >= 1.0
    )
    third_surface_closed = novelty_gate_pass and overlap_free and distinct_from_promoted and reserve_holds

    promoted_family_count = int(lane_b_family_scorecard.get("hydrated_family_count", 0))
    total_executed_family_like_surfaces = promoted_family_count + (1 if third_surface_closed else 0)

    packet = {
        "schema_id": "kt.operator.cohort0_successor_third_surface_breadth_witness_wave_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This wave closes the third-surface breadth question only. "
            "It does not authorize counted reentry, reopen Gate D, or open Gate E."
        ),
        "execution_status": EXECUTION_STATUS,
        "third_surface_candidate": {
            "family_id": reserve_family_id,
            "novelty_gate_pass": novelty_gate_pass,
            "legacy_ring_overlap_detected": bool(reserve_family.get("legacy_ring_overlap_detected", False)),
            "current_ring_overlap_detected": bool(reserve_family.get("current_ring_overlap_detected", False)),
            "distinct_from_promoted_family_lane": distinct_from_promoted,
            "visible_case_count": int(reserve_family.get("visible_case_count", 0)),
            "held_out_case_count": int(reserve_family.get("held_out_case_count", 0)),
        },
        "third_surface_reserve_metrics": reserve_metrics,
        "promoted_family_count_before_third_surface": promoted_family_count,
        "executed_family_like_surface_count_after_third_surface": total_executed_family_like_surfaces,
        "third_surface_breadth_witness_closed": third_surface_closed,
        "subject_head": subject_head,
    }

    receipt = {
        "schema_id": "kt.operator.cohort0_successor_third_surface_breadth_witness_wave_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "third_surface_breadth_witness_executed": True,
        "third_surface_breadth_witness_closed": third_surface_closed,
        "same_head_counted_reentry_admissible_now": False,
        "gate_d_reopened": False,
        "gate_e_open": False,
        "next_lawful_move": (
            "RECOMPUTE_SUCCESSOR_PREDICATES_AFTER_THIRD_SURFACE_WAVE"
            if third_surface_closed
            else "REPAIR_OR_REPLACE_THIRD_SURFACE_WITNESS_BEFORE_RECOMPUTING_SUCCESSOR_PREDICATES"
        ),
        "subject_head": subject_head,
    }
    return {"packet": packet, "receipt": receipt}


def _build_report(*, packet: Dict[str, Any], receipt: Dict[str, Any]) -> str:
    candidate = dict(packet.get("third_surface_candidate", {}))
    return (
        "# Cohort0 Successor Third-Surface Breadth Witness Wave Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Third-surface witness executed: `{receipt.get('third_surface_breadth_witness_executed', False)}`\n"
        f"- Third-surface witness closed: `{receipt.get('third_surface_breadth_witness_closed', False)}`\n"
        f"- Counted reentry admissible now: `{receipt.get('same_head_counted_reentry_admissible_now', False)}`\n"
        f"- Gate D reopened: `{receipt.get('gate_d_reopened', False)}`\n"
        f"- Gate E open: `{receipt.get('gate_e_open', False)}`\n"
        f"- Next lawful move: `{receipt.get('next_lawful_move', '')}`\n\n"
        "## Third Surface Candidate\n"
        f"- Family id: `{candidate.get('family_id', '')}`\n"
        f"- Novelty gate pass: `{candidate.get('novelty_gate_pass', False)}`\n"
        f"- Distinct from promoted family lane: `{candidate.get('distinct_from_promoted_family_lane', False)}`\n"
        f"- Legacy overlap detected: `{candidate.get('legacy_ring_overlap_detected', False)}`\n"
        f"- Current ring overlap detected: `{candidate.get('current_ring_overlap_detected', False)}`\n"
        f"- Visible cases: `{candidate.get('visible_case_count', 0)}`\n"
        f"- Held-out cases: `{candidate.get('held_out_case_count', 0)}`\n\n"
        "## Reserve Metrics\n"
        f"- Bridge exact: `{packet.get('third_surface_reserve_metrics', {}).get('bridge_reason_exact_accuracy', 0.0)}`\n"
        f"- Bridge admissible: `{packet.get('third_surface_reserve_metrics', {}).get('bridge_reason_admissible_accuracy', 0.0)}`\n"
        f"- Route consequence visible: `{packet.get('third_surface_reserve_metrics', {}).get('route_consequence_visible_rate', 0.0)}`\n"
        f"- Family-like surfaces after closure: `{packet.get('executed_family_like_surface_count_after_third_surface', 0)}`\n"
    )


def run(
    *,
    verdict_packet_path: Path,
    reentry_block_path: Path,
    lane_b_dual_scorecard_path: Path,
    lane_b_reserve_scorecard_path: Path,
    lane_b_family_scorecard_path: Path,
    narrow_review_receipt_path: Path,
    reports_root: Path,
) -> Dict[str, Any]:
    verdict_packet = _load_json_required(verdict_packet_path, label="hardened ceiling verdict packet")
    reentry_block = _load_json_required(reentry_block_path, label="gate d reentry block contract")
    lane_b_dual_scorecard = _load_json_required(lane_b_dual_scorecard_path, label="dual-lane lane b scorecard")
    lane_b_reserve_scorecard = _load_json_required(
        lane_b_reserve_scorecard_path, label="lane b reserve challenge scorecard"
    )
    lane_b_family_scorecard = _load_json_required(lane_b_family_scorecard_path, label="lane b family-level scorecard")
    narrow_review_receipt = _load_json_required(narrow_review_receipt_path, label="narrow review receipt")

    _validate_inputs(
        verdict_packet=verdict_packet,
        reentry_block=reentry_block,
        lane_b_dual_scorecard=lane_b_dual_scorecard,
        lane_b_reserve_scorecard=lane_b_reserve_scorecard,
        lane_b_family_scorecard=lane_b_family_scorecard,
        narrow_review_receipt=narrow_review_receipt,
    )
    subject_head = _require_same_subject_head(
        (
            verdict_packet,
            reentry_block,
            lane_b_dual_scorecard,
            lane_b_reserve_scorecard,
            lane_b_family_scorecard,
            narrow_review_receipt,
        )
    )

    outputs = _build_outputs(
        lane_b_dual_scorecard=lane_b_dual_scorecard,
        lane_b_reserve_scorecard=lane_b_reserve_scorecard,
        lane_b_family_scorecard=lane_b_family_scorecard,
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
        "third_surface_breadth_witness_closed": outputs["receipt"]["third_surface_breadth_witness_closed"],
        "output_count": 3,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Bind one additional distinct breadth witness on the successor line without widening claim scope."
    )
    parser.add_argument("--verdict-packet", default=DEFAULT_VERDICT_PACKET_REL)
    parser.add_argument("--reentry-block", default=DEFAULT_REENTRY_BLOCK_REL)
    parser.add_argument("--lane-b-dual-scorecard", default=DEFAULT_LANE_B_DUAL_SCORECARD_REL)
    parser.add_argument("--lane-b-reserve-scorecard", default=DEFAULT_LANE_B_RESERVE_SCORECARD_REL)
    parser.add_argument("--lane-b-family-scorecard", default=DEFAULT_LANE_B_FAMILY_SCORECARD_REL)
    parser.add_argument("--narrow-review-receipt", default=DEFAULT_NARROW_REVIEW_RECEIPT_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    args = parser.parse_args(argv)

    root = repo_root()
    result = run(
        verdict_packet_path=_resolve(root, args.verdict_packet),
        reentry_block_path=_resolve(root, args.reentry_block),
        lane_b_dual_scorecard_path=_resolve(root, args.lane_b_dual_scorecard),
        lane_b_reserve_scorecard_path=_resolve(root, args.lane_b_reserve_scorecard),
        lane_b_family_scorecard_path=_resolve(root, args.lane_b_family_scorecard),
        narrow_review_receipt_path=_resolve(root, args.narrow_review_receipt),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in (
        "status",
        "execution_status",
        "third_surface_breadth_witness_closed",
        "output_count",
        "receipt_path",
        "subject_head",
    ):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
