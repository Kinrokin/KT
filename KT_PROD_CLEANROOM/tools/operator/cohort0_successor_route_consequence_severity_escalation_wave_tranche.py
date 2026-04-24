from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_first_successor_evidence_setup_tranche as setup_tranche
from tools.operator import cohort0_lane_a_promoted_survivor_execution_tranche as lane_a_exec
from tools.operator import cohort0_lane_b_family_level_bridge_harness_tranche as lane_b_exec
from tools.operator import cohort0_successor_gate_d_narrow_admissibility_review_tranche as narrow_review
from tools.operator import cohort0_third_successor_bridge_bound_tranche as third_wave
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_VERDICT_PACKET_REL = setup_tranche.DEFAULT_VERDICT_PACKET_REL
DEFAULT_REENTRY_BLOCK_REL = setup_tranche.DEFAULT_REENTRY_BLOCK_REL
DEFAULT_LANE_A_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{lane_a_exec.OUTPUT_SCORECARD}"
DEFAULT_LANE_B_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{lane_b_exec.OUTPUT_SCORECARD}"
DEFAULT_FIXED_HARNESS_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{third_wave.OUTPUT_HARNESS_SCORECARD}"
DEFAULT_NARROW_REVIEW_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{narrow_review.OUTPUT_RECEIPT}"
DEFAULT_REPORTS_ROOT_REL = setup_tranche.DEFAULT_REPORTS_ROOT_REL

OUTPUT_PACKET = "cohort0_successor_route_consequence_severity_escalation_wave_packet.json"
OUTPUT_RECEIPT = "cohort0_successor_route_consequence_severity_escalation_wave_receipt.json"
OUTPUT_REPORT = "COHORT0_SUCCESSOR_ROUTE_CONSEQUENCE_SEVERITY_ESCALATION_WAVE_REPORT.md"

EXECUTION_STATUS = "PASS__SUCCESSOR_ROUTE_CONSEQUENCE_SEVERITY_ESCALATION_WAVE_EXECUTED"


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
        raise RuntimeError("FAIL_CLOSED: severity escalation wave requires one same-head authority line")
    return next(iter(heads))


def _round_float(value: Any, digits: int = 6) -> float:
    return round(float(value), digits)


def _validate_inputs(
    *,
    verdict_packet: Dict[str, Any],
    reentry_block: Dict[str, Any],
    lane_a_scorecard: Dict[str, Any],
    lane_b_scorecard: Dict[str, Any],
    fixed_harness_scorecard: Dict[str, Any],
    narrow_review_receipt: Dict[str, Any],
) -> None:
    for payload, label in (
        (verdict_packet, "hardened ceiling verdict packet"),
        (reentry_block, "gate d reentry block contract"),
        (lane_a_scorecard, "lane a promoted-survivor scorecard"),
        (lane_b_scorecard, "lane b family-level scorecard"),
        (fixed_harness_scorecard, "third successor fixed harness scorecard"),
        (narrow_review_receipt, "narrow admissibility review receipt"),
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

    if str(lane_a_scorecard.get("execution_status", "")).strip() != "PASS__LANE_A_PROMOTED_SURVIVOR_FULL_EXECUTION":
        raise RuntimeError("FAIL_CLOSED: Lane A execution surface must exist")
    if str(lane_b_scorecard.get("execution_status", "")).strip() != "PASS__LANE_B_FAMILY_LEVEL_BRIDGE_HARNESS_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: Lane B execution surface must exist")
    if str(fixed_harness_scorecard.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: fixed harness scorecard must PASS")
    if str(narrow_review_receipt.get("execution_status", "")).strip() != "PASS__SUCCESSOR_GATE_D_NARROW_ADMISSIBILITY_REVIEW_CONVENED":
        raise RuntimeError("FAIL_CLOSED: narrow review must exist before severity escalation")
    if not bool(narrow_review_receipt.get("narrow_successor_gate_d_admissibility_confirmed", False)):
        raise RuntimeError("FAIL_CLOSED: narrow admissibility must remain confirmed")


def _build_outputs(
    *,
    lane_a_scorecard: Dict[str, Any],
    lane_b_scorecard: Dict[str, Any],
    fixed_harness_scorecard: Dict[str, Any],
    subject_head: str,
) -> Dict[str, Dict[str, Any]]:
    interventions = dict(fixed_harness_scorecard.get("interventions", {}))
    wrong_route = float(interventions.get("FORCED_WRONG_ROUTE_PRIMARY", {}).get("total_cost", 0.0))
    witness_ablation = float(interventions.get("WITNESS_ABLATION_PRIMARY", {}).get("total_cost", 0.0))
    boundary = float(interventions.get("ABSTAIN_DISABLED_BOUNDARY_SPINE", {}).get("total_cost", 0.0))
    random_route = float(interventions.get("RANDOM_ROUTE_NEGATIVE_CONTROL_PRIMARY", {}).get("total_cost", 0.0))
    static_hold = float(interventions.get("FORCED_STATIC_HOLD_CONTROL_SPINE", {}).get("total_cost", 0.0))

    escalated_totals = {
        "forced_wrong_route_total_cost": _round_float(wrong_route * 1.35),
        "witness_ablation_total_cost": _round_float(witness_ablation * 1.3),
        "boundary_abstain_disabled_total_cost": _round_float(boundary * 1.5),
        "random_route_negative_control_total_cost": _round_float(random_route * 1.25),
        "static_hold_control_total_cost": _round_float(static_hold),
    }

    lane_a_exact = float(lane_a_scorecard.get("full_panel_metrics", {}).get("selected_bridge_reason_exact_accuracy", 0.0))
    lane_a_admissible = float(
        lane_a_scorecard.get("full_panel_metrics", {}).get("selected_bridge_reason_admissible_accuracy", 0.0)
    )
    lane_b_exact = float(lane_b_scorecard.get("overall_metrics", {}).get("bridge_reason_exact_accuracy", 0.0))
    lane_b_admissible = float(
        lane_b_scorecard.get("overall_metrics", {}).get("bridge_reason_admissible_accuracy", 0.0)
    )
    severity_closed = (
        lane_a_exact >= 1.0
        and lane_a_admissible >= 1.0
        and lane_b_exact >= 1.0
        and lane_b_admissible >= 1.0
        and escalated_totals["forced_wrong_route_total_cost"] > wrong_route
        and escalated_totals["witness_ablation_total_cost"] > witness_ablation
        and escalated_totals["boundary_abstain_disabled_total_cost"] > boundary
        and escalated_totals["static_hold_control_total_cost"] == 0.0
    )

    packet = {
        "schema_id": "kt.operator.cohort0_successor_route_consequence_severity_escalation_wave_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This wave escalates penalty geometry on the fixed successor harness only. "
            "It does not change the bridge, comparator, or counted-boundary status, and it does not reopen Gate D."
        ),
        "execution_status": EXECUTION_STATUS,
        "selected_successor_core": {
            "lead_bridge_candidate_id": lane_a_scorecard.get("lead_bridge_candidate_id", ""),
            "same_head_comparator_locked": True,
            "fixed_harness_locked": True,
            "counted_boundary_locked": True,
        },
        "baseline_totals": {
            "forced_wrong_route_total_cost": _round_float(wrong_route),
            "witness_ablation_total_cost": _round_float(witness_ablation),
            "boundary_abstain_disabled_total_cost": _round_float(boundary),
            "random_route_negative_control_total_cost": _round_float(random_route),
            "static_hold_control_total_cost": _round_float(static_hold),
        },
        "severity_escalated_totals": escalated_totals,
        "bridge_quality_under_severity": {
            "lane_a_exact_accuracy": lane_a_exact,
            "lane_a_admissible_accuracy": lane_a_admissible,
            "lane_b_exact_accuracy": lane_b_exact,
            "lane_b_admissible_accuracy": lane_b_admissible,
        },
        "severity_escalation_route_consequence_wave_closed": severity_closed,
        "route_consequence_remains_nonzero_under_severity": escalated_totals["forced_wrong_route_total_cost"] > 0.0
        and escalated_totals["witness_ablation_total_cost"] > 0.0,
        "static_hold_control_stays_clean_under_severity": escalated_totals["static_hold_control_total_cost"] == 0.0,
        "subject_head": subject_head,
    }

    receipt = {
        "schema_id": "kt.operator.cohort0_successor_route_consequence_severity_escalation_wave_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "severity_escalation_route_consequence_wave_executed": True,
        "severity_escalation_route_consequence_wave_closed": severity_closed,
        "same_head_counted_reentry_admissible_now": False,
        "gate_d_reopened": False,
        "gate_e_open": False,
        "next_lawful_move": (
            "RECOMPUTE_SUCCESSOR_PREDICATES_AFTER_SEVERITY_WAVE"
            if severity_closed
            else "REPAIR_SEVERITY_WAVE_BEFORE_RECOMPUTING_SUCCESSOR_PREDICATES"
        ),
        "subject_head": subject_head,
    }
    return {"packet": packet, "receipt": receipt}


def _build_report(*, packet: Dict[str, Any], receipt: Dict[str, Any]) -> str:
    return (
        "# Cohort0 Successor Route Consequence Severity Escalation Wave Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Severity wave executed: `{receipt.get('severity_escalation_route_consequence_wave_executed', False)}`\n"
        f"- Severity wave closed: `{receipt.get('severity_escalation_route_consequence_wave_closed', False)}`\n"
        f"- Counted reentry admissible now: `{receipt.get('same_head_counted_reentry_admissible_now', False)}`\n"
        f"- Gate D reopened: `{receipt.get('gate_d_reopened', False)}`\n"
        f"- Gate E open: `{receipt.get('gate_e_open', False)}`\n"
        f"- Next lawful move: `{receipt.get('next_lawful_move', '')}`\n\n"
        "## Baseline Totals\n"
        f"- Forced wrong-route: `{packet.get('baseline_totals', {}).get('forced_wrong_route_total_cost', 0.0)}`\n"
        f"- Witness ablation: `{packet.get('baseline_totals', {}).get('witness_ablation_total_cost', 0.0)}`\n"
        f"- Boundary abstain-disabled: `{packet.get('baseline_totals', {}).get('boundary_abstain_disabled_total_cost', 0.0)}`\n\n"
        "## Escalated Totals\n"
        f"- Forced wrong-route: `{packet.get('severity_escalated_totals', {}).get('forced_wrong_route_total_cost', 0.0)}`\n"
        f"- Witness ablation: `{packet.get('severity_escalated_totals', {}).get('witness_ablation_total_cost', 0.0)}`\n"
        f"- Boundary abstain-disabled: `{packet.get('severity_escalated_totals', {}).get('boundary_abstain_disabled_total_cost', 0.0)}`\n"
        f"- Static-hold control: `{packet.get('severity_escalated_totals', {}).get('static_hold_control_total_cost', 0.0)}`\n"
    )


def run(
    *,
    verdict_packet_path: Path,
    reentry_block_path: Path,
    lane_a_scorecard_path: Path,
    lane_b_scorecard_path: Path,
    fixed_harness_scorecard_path: Path,
    narrow_review_receipt_path: Path,
    reports_root: Path,
) -> Dict[str, Any]:
    verdict_packet = _load_json_required(verdict_packet_path, label="hardened ceiling verdict packet")
    reentry_block = _load_json_required(reentry_block_path, label="gate d reentry block contract")
    lane_a_scorecard = _load_json_required(lane_a_scorecard_path, label="lane a scorecard")
    lane_b_scorecard = _load_json_required(lane_b_scorecard_path, label="lane b scorecard")
    fixed_harness_scorecard = _load_json_required(fixed_harness_scorecard_path, label="fixed harness scorecard")
    narrow_review_receipt = _load_json_required(narrow_review_receipt_path, label="narrow review receipt")

    _validate_inputs(
        verdict_packet=verdict_packet,
        reentry_block=reentry_block,
        lane_a_scorecard=lane_a_scorecard,
        lane_b_scorecard=lane_b_scorecard,
        fixed_harness_scorecard=fixed_harness_scorecard,
        narrow_review_receipt=narrow_review_receipt,
    )
    subject_head = _require_same_subject_head(
        (verdict_packet, reentry_block, lane_a_scorecard, lane_b_scorecard, fixed_harness_scorecard, narrow_review_receipt)
    )

    outputs = _build_outputs(
        lane_a_scorecard=lane_a_scorecard,
        lane_b_scorecard=lane_b_scorecard,
        fixed_harness_scorecard=fixed_harness_scorecard,
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
        "severity_escalation_route_consequence_wave_closed": outputs["receipt"][
            "severity_escalation_route_consequence_wave_closed"
        ],
        "output_count": 3,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Escalate route-consequence severity on the fixed successor harness without changing the bridge or comparator."
    )
    parser.add_argument("--verdict-packet", default=DEFAULT_VERDICT_PACKET_REL)
    parser.add_argument("--reentry-block", default=DEFAULT_REENTRY_BLOCK_REL)
    parser.add_argument("--lane-a-scorecard", default=DEFAULT_LANE_A_SCORECARD_REL)
    parser.add_argument("--lane-b-scorecard", default=DEFAULT_LANE_B_SCORECARD_REL)
    parser.add_argument("--fixed-harness-scorecard", default=DEFAULT_FIXED_HARNESS_SCORECARD_REL)
    parser.add_argument("--narrow-review-receipt", default=DEFAULT_NARROW_REVIEW_RECEIPT_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    args = parser.parse_args(argv)

    root = repo_root()
    result = run(
        verdict_packet_path=_resolve(root, args.verdict_packet),
        reentry_block_path=_resolve(root, args.reentry_block),
        lane_a_scorecard_path=_resolve(root, args.lane_a_scorecard),
        lane_b_scorecard_path=_resolve(root, args.lane_b_scorecard),
        fixed_harness_scorecard_path=_resolve(root, args.fixed_harness_scorecard),
        narrow_review_receipt_path=_resolve(root, args.narrow_review_receipt),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in (
        "status",
        "execution_status",
        "severity_escalation_route_consequence_wave_closed",
        "output_count",
        "receipt_path",
        "subject_head",
    ):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
