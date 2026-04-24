from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_dual_lane_first_execution_tranche as dual_lane
from tools.operator import cohort0_first_successor_evidence_setup_tranche as setup_tranche
from tools.operator import cohort0_third_successor_bridge_bound_tranche as third_wave
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_VERDICT_PACKET_REL = setup_tranche.DEFAULT_VERDICT_PACKET_REL
DEFAULT_REENTRY_BLOCK_REL = setup_tranche.DEFAULT_REENTRY_BLOCK_REL
DEFAULT_DUAL_LANE_EXECUTION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{dual_lane.OUTPUT_EXECUTION_RECEIPT}"
DEFAULT_LANE_A_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{dual_lane.OUTPUT_LANE_A_SCORECARD}"
DEFAULT_THIRD_EXECUTION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{third_wave.OUTPUT_EXECUTION_RECEIPT}"
DEFAULT_THIRD_ROW_PANEL_REL = f"KT_PROD_CLEANROOM/reports/{third_wave.OUTPUT_ROW_PANEL}"
DEFAULT_THIRD_HARNESS_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{third_wave.OUTPUT_HARNESS_SCORECARD}"
DEFAULT_REPORTS_ROOT_REL = setup_tranche.DEFAULT_REPORTS_ROOT_REL

OUTPUT_ROW_PANEL = "cohort0_lane_a_promoted_survivor_row_panel.json"
OUTPUT_SCORECARD = "cohort0_lane_a_promoted_survivor_bridge_harness_scorecard.json"
OUTPUT_RECEIPT = "cohort0_lane_a_promoted_survivor_execution_receipt.json"
OUTPUT_REPORT = "COHORT0_LANE_A_PROMOTED_SURVIVOR_EXECUTION_REPORT.md"


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
        raise RuntimeError("FAIL_CLOSED: Lane A promoted-survivor execution requires one same-head authority line")
    return next(iter(heads))


def _round_float(value: Any, digits: int = 6) -> float:
    return round(float(value), digits)


def _bool_rate(flags: Sequence[bool]) -> float:
    if not flags:
        return 0.0
    return _round_float(sum(1 for item in flags if item) / len(flags))


def _weighted_rate(rows: Sequence[Dict[str, Any]], *, key: str, weight_key: str = "wrong_route_cost") -> float:
    if not rows:
        return 0.0
    total_weight = sum(float(row.get(weight_key, 0.0)) for row in rows)
    if total_weight <= 0.0:
        return 0.0
    matched_weight = sum(float(row.get(weight_key, 0.0)) for row in rows if bool(row.get(key, False)))
    return _round_float(matched_weight / total_weight)


def _validate_inputs(
    *,
    verdict_packet: Dict[str, Any],
    reentry_block: Dict[str, Any],
    dual_lane_execution_receipt: Dict[str, Any],
    lane_a_scorecard: Dict[str, Any],
    third_execution_receipt: Dict[str, Any],
    third_row_panel: Dict[str, Any],
    third_harness_scorecard: Dict[str, Any],
) -> None:
    for payload, label in (
        (verdict_packet, "hardened ceiling verdict packet"),
        (reentry_block, "gate d reentry block contract"),
        (dual_lane_execution_receipt, "dual-lane first execution receipt"),
        (lane_a_scorecard, "dual-lane lane a scorecard"),
        (third_execution_receipt, "third successor execution receipt"),
        (third_row_panel, "third successor bridge-bound row panel"),
        (third_harness_scorecard, "third successor fixed harness scorecard"),
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

    if str(dual_lane_execution_receipt.get("execution_status", "")).strip() != "PASS__DUAL_LANE_FIRST_CONCURRENT_SCREENING_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: dual-lane first concurrent screening must exist")
    if bool(dual_lane_execution_receipt.get("same_head_counted_reentry_admissible_now", True)):
        raise RuntimeError("FAIL_CLOSED: counted reentry must remain blocked entering Lane A promoted execution")
    if bool(dual_lane_execution_receipt.get("gate_d_reopened", True)):
        raise RuntimeError("FAIL_CLOSED: Gate D must remain closed entering Lane A promoted execution")
    if bool(dual_lane_execution_receipt.get("gate_e_open", True)):
        raise RuntimeError("FAIL_CLOSED: Gate E must remain closed entering Lane A promoted execution")

    if str(lane_a_scorecard.get("execution_status", "")).strip() != "PASS__LANE_A_FIRST_CONCURRENT_SCORING_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: lane a scorecard must be first-concurrent scoring output")
    if int(lane_a_scorecard.get("survivor_count", 0)) != 2:
        raise RuntimeError("FAIL_CLOSED: lane a promoted-survivor execution expects exactly two screened survivors")

    if str(third_execution_receipt.get("execution_status", "")).strip() != "PASS__THIRD_WAVE_BRIDGE_BOUND_STRENGTHENING_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: third-wave bridge-bound strengthening must exist")
    if str(third_execution_receipt.get("selected_bridge_candidate_id", "")).strip() != dual_lane.controller_tranche.LEAD_BRIDGE_ID:
        raise RuntimeError("FAIL_CLOSED: unexpected lead bridge candidate entering Lane A promoted execution")
    if not bool(third_execution_receipt.get("bridge_alignment_visible", False)):
        raise RuntimeError("FAIL_CLOSED: third-wave bridge alignment must remain visible")
    if not bool(third_execution_receipt.get("fixed_harness_route_consequence_signal_nonzero", False)):
        raise RuntimeError("FAIL_CLOSED: fixed harness must remain nonzero")
    if not bool(third_execution_receipt.get("fixed_harness_stable_vs_second_wave", False)):
        raise RuntimeError("FAIL_CLOSED: fixed harness must remain stable")

    signals = dict(third_harness_scorecard.get("signals", {}))
    if not bool(signals.get("route_consequence_signal_nonzero", False)):
        raise RuntimeError("FAIL_CLOSED: fixed harness scorecard must keep route consequence visible")
    if not bool(signals.get("stable_vs_second_wave", False)):
        raise RuntimeError("FAIL_CLOSED: fixed harness scorecard must stay stable versus second wave")


def _case_rows_by_id(third_row_panel: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {
        str(row.get("case_id", "")).strip(): row
        for row in third_row_panel.get("rows", [])
        if isinstance(row, dict) and str(row.get("case_id", "")).strip()
    }


def _masked_companion_id(case_id: str) -> str:
    return f"{case_id}__MASKED"


def _build_survivor_rows(
    *,
    lane_a_scorecard: Dict[str, Any],
    third_row_panel: Dict[str, Any],
) -> List[Dict[str, Any]]:
    rows_by_case = _case_rows_by_id(third_row_panel)
    survivor_rows: List[Dict[str, Any]] = []
    for survivor in lane_a_scorecard.get("survivors", []):
        if not isinstance(survivor, dict):
            continue
        case_id = str(survivor.get("source_case_id", "")).strip()
        if not case_id:
            continue
        primary_row = dict(rows_by_case.get(case_id, {}))
        if not primary_row:
            raise RuntimeError(f"FAIL_CLOSED: missing Lane A promoted survivor source row: {case_id}")
        masked_row = dict(rows_by_case.get(_masked_companion_id(case_id), {}))
        survivor_rows.append(
            {
                "mutation_candidate_id": str(survivor.get("mutation_candidate_id", "")).strip(),
                "source_case_id": case_id,
                "source_family_id": str(survivor.get("source_family_id", "")).strip(),
                "source_legacy_family_id": str(survivor.get("source_legacy_family_id", "")).strip(),
                "selected_bridge_reason_label": str(survivor.get("selected_bridge_reason_label", "")).strip(),
                "primary_case_row": primary_row,
                "masked_companion_row": masked_row if masked_row else None,
                "screening_composite_priority_score": _round_float(survivor.get("composite_priority_score", 0.0)),
            }
        )
    return survivor_rows


def _flat_rows(survivor_rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in survivor_rows:
        primary_row = dict(item.get("primary_case_row", {}))
        primary_row["panel_role"] = "promoted_primary"
        primary_row["mutation_candidate_id"] = item["mutation_candidate_id"]
        rows.append(primary_row)
        masked = item.get("masked_companion_row")
        if isinstance(masked, dict) and masked:
            masked_row = dict(masked)
            masked_row["panel_role"] = "masked_companion"
            masked_row["mutation_candidate_id"] = item["mutation_candidate_id"]
            rows.append(masked_row)
    return rows


def _score_rows(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "row_count": len(rows),
        "action_accuracy": _bool_rate(
            [str(row.get("predicted_action_label", "")).strip() == str(row.get("lawful_action", "")).strip() for row in rows]
        ),
        "why_not_accuracy": _bool_rate(
            [
                str(row.get("predicted_why_not_label", "")).strip()
                == str(row.get("gold_why_not_target_label", "")).strip()
                for row in rows
            ]
        ),
        "baseline_reason_exact_accuracy": _bool_rate([bool(row.get("baseline_reason_exact", False)) for row in rows]),
        "baseline_reason_admissible_accuracy": _bool_rate([bool(row.get("baseline_reason_admissible", False)) for row in rows]),
        "selected_bridge_reason_exact_accuracy": _bool_rate(
            [bool(row.get("selected_bridge_reason_exact", False)) for row in rows]
        ),
        "selected_bridge_reason_admissible_accuracy": _bool_rate(
            [bool(row.get("selected_bridge_reason_admissible", False)) for row in rows]
        ),
        "selected_bridge_consequence_weighted_exact_accuracy": _weighted_rate(
            rows, key="selected_bridge_reason_exact", weight_key="wrong_route_cost"
        ),
        "selected_bridge_consequence_weighted_admissible_accuracy": _weighted_rate(
            rows, key="selected_bridge_reason_admissible", weight_key="wrong_route_cost"
        ),
        "total_wrong_route_cost": _round_float(sum(float(row.get("wrong_route_cost", 0.0)) for row in rows)),
        "total_wrong_static_hold_cost": _round_float(sum(float(row.get("wrong_static_hold_cost", 0.0)) for row in rows)),
        "total_missed_abstention_cost": _round_float(sum(float(row.get("missed_abstention_cost", 0.0)) for row in rows)),
        "mean_observed_route_margin": _round_float(
            sum(float(row.get("observed_route_margin", 0.0)) for row in rows) / max(1, len(rows))
        ),
    }


def _build_outputs(
    *,
    survivor_rows: Sequence[Dict[str, Any]],
    third_harness_scorecard: Dict[str, Any],
    subject_head: str,
) -> Dict[str, Any]:
    primary_rows = [dict(item["primary_case_row"]) for item in survivor_rows]
    companion_rows = [
        dict(item["masked_companion_row"])
        for item in survivor_rows
        if isinstance(item.get("masked_companion_row"), dict) and item.get("masked_companion_row")
    ]
    full_panel_rows = _flat_rows(survivor_rows)

    primary_metrics = _score_rows(primary_rows)
    full_panel_metrics = _score_rows(full_panel_rows)
    companion_metrics = _score_rows(companion_rows) if companion_rows else {"row_count": 0}

    full_bridge_hold = all(bool(row.get("selected_bridge_reason_exact", False)) for row in full_panel_rows) and all(
        bool(row.get("selected_bridge_reason_admissible", False)) for row in full_panel_rows
    )
    bridge_exact_lift = _round_float(
        full_panel_metrics["selected_bridge_reason_exact_accuracy"] - full_panel_metrics["baseline_reason_exact_accuracy"]
    )
    bridge_admissible_lift = _round_float(
        full_panel_metrics["selected_bridge_reason_admissible_accuracy"]
        - full_panel_metrics["baseline_reason_admissible_accuracy"]
    )

    interventions = dict(third_harness_scorecard.get("interventions", {}))
    fixed_harness_totals = {
        "forced_wrong_route_total_cost": _round_float(
            interventions.get("FORCED_WRONG_ROUTE_PRIMARY", {}).get("total_cost", 0.0)
        ),
        "witness_ablation_total_cost": _round_float(
            interventions.get("WITNESS_ABLATION_PRIMARY", {}).get("total_cost", 0.0)
        ),
        "boundary_abstain_disabled_total_cost": _round_float(
            interventions.get("BOUNDARY_ABSTAIN_DISABLED_PRIMARY", {}).get("total_cost", 0.0)
        ),
        "static_hold_control_total_cost": _round_float(
            interventions.get("FORCED_STATIC_HOLD_CONTROL", {}).get("total_cost", 0.0)
        ),
    }

    scorecard = {
        "schema_id": "kt.operator.cohort0_lane_a_promoted_survivor_bridge_harness_scorecard.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This scorecard executes full bridge+harness scoring on the two promoted Lane A survivor case rows "
            "already live on the saved-head bridge-bound panel. It does not claim generated mutation-text execution, "
            "counted reentry, Gate D reopening, or Gate E opening."
        ),
        "execution_status": "PASS__LANE_A_PROMOTED_SURVIVOR_FULL_EXECUTION",
        "lead_bridge_candidate_id": dual_lane.controller_tranche.LEAD_BRIDGE_ID,
        "primary_survivor_case_count": len(primary_rows),
        "masked_companion_case_count": len(companion_rows),
        "full_panel_case_count": len(full_panel_rows),
        "primary_panel_metrics": primary_metrics,
        "masked_companion_metrics": companion_metrics,
        "full_panel_metrics": full_panel_metrics,
        "bridge_exact_lift": bridge_exact_lift,
        "bridge_admissible_lift": bridge_admissible_lift,
        "full_bridge_hold": full_bridge_hold,
        "local_route_consequence_signal_nonzero": full_panel_metrics["total_wrong_route_cost"] > 0.0,
        "fixed_harness_global_totals": fixed_harness_totals,
        "survivor_rows": survivor_rows,
        "subject_head": subject_head,
    }

    row_panel = {
        "schema_id": "kt.operator.cohort0_lane_a_promoted_survivor_row_panel.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": scorecard["claim_boundary"],
        "lead_bridge_candidate_id": dual_lane.controller_tranche.LEAD_BRIDGE_ID,
        "rows": full_panel_rows,
        "subject_head": subject_head,
    }

    receipt = {
        "schema_id": "kt.operator.cohort0_lane_a_promoted_survivor_execution_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This receipt records promoted Lane A survivor bridge+harness execution only. "
            "It does not reopen Gate D, authorize counted reentry, or open Gate E."
        ),
        "execution_status": "PASS__LANE_A_PROMOTED_SURVIVOR_FULL_EXECUTION",
        "lead_bridge_candidate_id": dual_lane.controller_tranche.LEAD_BRIDGE_ID,
        "promoted_survivor_case_count": len(primary_rows),
        "masked_companion_case_count": len(companion_rows),
        "bridge_exact_lift_observed": bridge_exact_lift > 0.0,
        "bridge_admissible_lift_observed": bridge_admissible_lift > 0.0,
        "full_bridge_hold": full_bridge_hold,
        "local_route_consequence_signal_nonzero": full_panel_metrics["total_wrong_route_cost"] > 0.0,
        "same_head_counted_reentry_admissible_now": False,
        "gate_d_reopened": False,
        "gate_e_open": False,
        "subject_head": subject_head,
    }
    return {"row_panel": row_panel, "scorecard": scorecard, "receipt": receipt}


def _build_report(*, scorecard: Dict[str, Any], receipt: Dict[str, Any]) -> str:
    primary = dict(scorecard.get("primary_panel_metrics", {}))
    full_panel = dict(scorecard.get("full_panel_metrics", {}))
    fixed_harness = dict(scorecard.get("fixed_harness_global_totals", {}))
    survivors = list(scorecard.get("survivor_rows", []))
    survivor_lines = "\n".join(
        f"- `{item.get('mutation_candidate_id', '')}` -> `{item.get('source_case_id', '')}` ({item.get('source_family_id', '')})"
        for item in survivors
    )
    return (
        "# Cohort0 Lane A Promoted Survivor Execution Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Lead bridge: `{receipt.get('lead_bridge_candidate_id', '')}`\n"
        f"- Promoted survivor case count: `{receipt.get('promoted_survivor_case_count', 0)}`\n"
        f"- Masked companion case count: `{receipt.get('masked_companion_case_count', 0)}`\n"
        f"- Bridge exact lift observed: `{receipt.get('bridge_exact_lift_observed', False)}`\n"
        f"- Bridge admissible lift observed: `{receipt.get('bridge_admissible_lift_observed', False)}`\n"
        f"- Full bridge hold: `{receipt.get('full_bridge_hold', False)}`\n"
        f"- Local route consequence signal nonzero: `{receipt.get('local_route_consequence_signal_nonzero', False)}`\n"
        f"- Counted reentry admissible now: `{receipt.get('same_head_counted_reentry_admissible_now', True)}`\n"
        f"- Gate D reopened: `{receipt.get('gate_d_reopened', True)}`\n"
        f"- Gate E open: `{receipt.get('gate_e_open', True)}`\n\n"
        "## Promoted Survivors\n"
        f"{survivor_lines}\n\n"
        "## Primary Panel Metrics\n"
        f"- Baseline reason exact: `{primary.get('baseline_reason_exact_accuracy', 0.0)}`\n"
        f"- Baseline reason admissible: `{primary.get('baseline_reason_admissible_accuracy', 0.0)}`\n"
        f"- Selected bridge reason exact: `{primary.get('selected_bridge_reason_exact_accuracy', 0.0)}`\n"
        f"- Selected bridge reason admissible: `{primary.get('selected_bridge_reason_admissible_accuracy', 0.0)}`\n"
        f"- Total wrong-route cost: `{primary.get('total_wrong_route_cost', 0.0)}`\n"
        f"- Mean observed route margin: `{primary.get('mean_observed_route_margin', 0.0)}`\n\n"
        "## Full Panel Metrics\n"
        f"- Full panel case count: `{scorecard.get('full_panel_case_count', 0)}`\n"
        f"- Selected bridge weighted exact: `{full_panel.get('selected_bridge_consequence_weighted_exact_accuracy', 0.0)}`\n"
        f"- Selected bridge weighted admissible: `{full_panel.get('selected_bridge_consequence_weighted_admissible_accuracy', 0.0)}`\n"
        f"- Total wrong-route cost: `{full_panel.get('total_wrong_route_cost', 0.0)}`\n"
        f"- Total wrong-static-hold cost: `{full_panel.get('total_wrong_static_hold_cost', 0.0)}`\n\n"
        "## Fixed Harness Context\n"
        f"- Forced wrong-route total cost: `{fixed_harness.get('forced_wrong_route_total_cost', 0.0)}`\n"
        f"- Witness ablation total cost: `{fixed_harness.get('witness_ablation_total_cost', 0.0)}`\n"
        f"- Boundary abstain-disabled total cost: `{fixed_harness.get('boundary_abstain_disabled_total_cost', 0.0)}`\n"
        f"- Static-hold control total cost: `{fixed_harness.get('static_hold_control_total_cost', 0.0)}`\n"
    )


def run(
    *,
    verdict_packet_path: Path,
    reentry_block_path: Path,
    dual_lane_execution_receipt_path: Path,
    lane_a_scorecard_path: Path,
    third_execution_receipt_path: Path,
    third_row_panel_path: Path,
    third_harness_scorecard_path: Path,
    reports_root: Path,
) -> Dict[str, Any]:
    verdict_packet = _load_json_required(verdict_packet_path, label="hardened ceiling verdict packet")
    reentry_block = _load_json_required(reentry_block_path, label="gate d reentry block contract")
    dual_lane_execution_receipt = _load_json_required(
        dual_lane_execution_receipt_path, label="dual-lane first execution receipt"
    )
    lane_a_scorecard = _load_json_required(lane_a_scorecard_path, label="dual-lane lane a scorecard")
    third_execution_receipt = _load_json_required(third_execution_receipt_path, label="third successor execution receipt")
    third_row_panel = _load_json_required(third_row_panel_path, label="third successor bridge-bound row panel")
    third_harness_scorecard = _load_json_required(
        third_harness_scorecard_path, label="third successor fixed harness scorecard"
    )

    _validate_inputs(
        verdict_packet=verdict_packet,
        reentry_block=reentry_block,
        dual_lane_execution_receipt=dual_lane_execution_receipt,
        lane_a_scorecard=lane_a_scorecard,
        third_execution_receipt=third_execution_receipt,
        third_row_panel=third_row_panel,
        third_harness_scorecard=third_harness_scorecard,
    )
    subject_head = _require_same_subject_head(
        (
            verdict_packet,
            reentry_block,
            dual_lane_execution_receipt,
            lane_a_scorecard,
            third_execution_receipt,
            third_row_panel,
            third_harness_scorecard,
        )
    )

    survivor_rows = _build_survivor_rows(lane_a_scorecard=lane_a_scorecard, third_row_panel=third_row_panel)
    outputs = _build_outputs(
        survivor_rows=survivor_rows,
        third_harness_scorecard=third_harness_scorecard,
        subject_head=subject_head,
    )

    reports_root.mkdir(parents=True, exist_ok=True)
    row_panel_path = reports_root / OUTPUT_ROW_PANEL
    scorecard_path = reports_root / OUTPUT_SCORECARD
    receipt_path = reports_root / OUTPUT_RECEIPT
    report_path = reports_root / OUTPUT_REPORT

    write_json_stable(row_panel_path, outputs["row_panel"])
    write_json_stable(scorecard_path, outputs["scorecard"])
    write_json_stable(receipt_path, outputs["receipt"])
    _write_text(report_path, _build_report(scorecard=outputs["scorecard"], receipt=outputs["receipt"]))

    return {
        "status": "PASS",
        "execution_status": outputs["receipt"]["execution_status"],
        "bridge_exact_lift_observed": outputs["receipt"]["bridge_exact_lift_observed"],
        "local_route_consequence_signal_nonzero": outputs["receipt"]["local_route_consequence_signal_nonzero"],
        "promoted_survivor_case_count": outputs["receipt"]["promoted_survivor_case_count"],
        "output_count": 4,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Execute full bridge+harness scoring on the two promoted Lane A survivor cases."
    )
    parser.add_argument("--verdict-packet", default=DEFAULT_VERDICT_PACKET_REL)
    parser.add_argument("--reentry-block", default=DEFAULT_REENTRY_BLOCK_REL)
    parser.add_argument("--dual-lane-execution-receipt", default=DEFAULT_DUAL_LANE_EXECUTION_RECEIPT_REL)
    parser.add_argument("--lane-a-scorecard", default=DEFAULT_LANE_A_SCORECARD_REL)
    parser.add_argument("--third-execution-receipt", default=DEFAULT_THIRD_EXECUTION_RECEIPT_REL)
    parser.add_argument("--third-row-panel", default=DEFAULT_THIRD_ROW_PANEL_REL)
    parser.add_argument("--third-harness-scorecard", default=DEFAULT_THIRD_HARNESS_SCORECARD_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    args = parser.parse_args(argv)

    root = repo_root()
    result = run(
        verdict_packet_path=_resolve(root, args.verdict_packet),
        reentry_block_path=_resolve(root, args.reentry_block),
        dual_lane_execution_receipt_path=_resolve(root, args.dual_lane_execution_receipt),
        lane_a_scorecard_path=_resolve(root, args.lane_a_scorecard),
        third_execution_receipt_path=_resolve(root, args.third_execution_receipt),
        third_row_panel_path=_resolve(root, args.third_row_panel),
        third_harness_scorecard_path=_resolve(root, args.third_harness_scorecard),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in (
        "status",
        "execution_status",
        "bridge_exact_lift_observed",
        "local_route_consequence_signal_nonzero",
        "promoted_survivor_case_count",
        "output_count",
        "receipt_path",
        "subject_head",
    ):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
