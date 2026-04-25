from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_lane_a_promoted_survivor_execution_tranche as lane_a
from tools.operator import cohort0_lane_b_stage_pack_hydration_tranche as lane_b_hydration
from tools.operator import cohort0_first_successor_evidence_setup_tranche as setup_tranche
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_VERDICT_PACKET_REL = setup_tranche.DEFAULT_VERDICT_PACKET_REL
DEFAULT_REENTRY_BLOCK_REL = setup_tranche.DEFAULT_REENTRY_BLOCK_REL
DEFAULT_LANE_A_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{lane_a.OUTPUT_RECEIPT}"
DEFAULT_LANE_A_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{lane_a.OUTPUT_SCORECARD}"
DEFAULT_LANE_B_HYDRATION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{lane_b_hydration.OUTPUT_HYDRATION_RECEIPT}"
DEFAULT_LANE_B_HYDRATED_CASE_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{lane_b_hydration.OUTPUT_HYDRATED_CASE_PACKET}"
DEFAULT_REPORTS_ROOT_REL = setup_tranche.DEFAULT_REPORTS_ROOT_REL

OUTPUT_ROW_PANEL = "cohort0_lane_b_family_level_row_panel.json"
OUTPUT_SCORECARD = "cohort0_lane_b_family_level_bridge_harness_scorecard.json"
OUTPUT_COMPARATIVE_PACKET = "cohort0_cross_lane_bridge_harness_comparative_packet.json"
OUTPUT_RECEIPT = "cohort0_lane_b_family_level_execution_receipt.json"
OUTPUT_REPORT = "COHORT0_LANE_B_FAMILY_LEVEL_EXECUTION_REPORT.md"


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
        raise RuntimeError("FAIL_CLOSED: Lane B family-level bridge execution requires one same-head authority line")
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
    lane_a_receipt: Dict[str, Any],
    lane_a_scorecard: Dict[str, Any],
    lane_b_hydration_receipt: Dict[str, Any],
    lane_b_hydrated_case_packet: Dict[str, Any],
) -> None:
    for payload, label in (
        (verdict_packet, "hardened ceiling verdict packet"),
        (reentry_block, "gate d reentry block contract"),
        (lane_a_receipt, "lane a promoted-survivor execution receipt"),
        (lane_a_scorecard, "lane a promoted-survivor scorecard"),
        (lane_b_hydration_receipt, "lane b hydration receipt"),
        (lane_b_hydrated_case_packet, "lane b hydrated case packet"),
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

    if str(lane_a_receipt.get("execution_status", "")).strip() != "PASS__LANE_A_PROMOTED_SURVIVOR_FULL_EXECUTION":
        raise RuntimeError("FAIL_CLOSED: lane a promoted-survivor execution must exist before Lane B family execution")
    if bool(lane_a_receipt.get("same_head_counted_reentry_admissible_now", True)):
        raise RuntimeError("FAIL_CLOSED: counted reentry must remain blocked entering Lane B family execution")
    if bool(lane_a_receipt.get("gate_d_reopened", True)):
        raise RuntimeError("FAIL_CLOSED: Gate D must remain closed entering Lane B family execution")
    if bool(lane_a_receipt.get("gate_e_open", True)):
        raise RuntimeError("FAIL_CLOSED: Gate E must remain closed entering Lane B family execution")

    if str(lane_b_hydration_receipt.get("execution_status", "")).strip() != "PASS__LANE_B_STAGE_PACK_HYDRATION_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: Lane B hydration must exist before family-level execution")
    if not bool(lane_b_hydration_receipt.get("lane_b_case_execution_available_after_hydration", False)):
        raise RuntimeError("FAIL_CLOSED: Lane B case execution must be available after hydration")
    if bool(lane_b_hydration_receipt.get("same_head_counted_reentry_admissible_now", True)):
        raise RuntimeError("FAIL_CLOSED: counted reentry must remain blocked entering Lane B family execution")
    if bool(lane_b_hydration_receipt.get("gate_d_reopened", True)):
        raise RuntimeError("FAIL_CLOSED: Gate D must remain closed entering Lane B family execution")
    if bool(lane_b_hydration_receipt.get("gate_e_open", True)):
        raise RuntimeError("FAIL_CLOSED: Gate E must remain closed entering Lane B family execution")

    if int(lane_b_hydrated_case_packet.get("hydrated_family_count", 0)) < 1:
        raise RuntimeError("FAIL_CLOSED: Lane B hydrated case packet must contain at least one family")


def _expected_route_justification(*, adapter_id: str, alpha_liability: str) -> str:
    liability = str(alpha_liability).strip()
    if liability and not liability.endswith("."):
        liability = f"{liability}."
    return f"Route to {adapter_id} because {liability}".strip()


def _safe_effect_visible(value: str) -> bool:
    return str(value).strip() == "ROUTE_EXPECTED_TO_REDUCE_ALPHA_LIABILITY"


def _row_from_case(family: Dict[str, Any], case_row: Dict[str, Any]) -> Dict[str, Any]:
    adapter_id = str(family.get("adapter_id", "")).strip()
    preferred_policy_outcome = str(family.get("preferred_policy_outcome", "")).strip()
    route_justification = str(case_row.get("route_justification", "")).strip()
    expected_justification = _expected_route_justification(
        adapter_id=adapter_id,
        alpha_liability=str(family.get("alpha_liability", "")).strip(),
    )
    selected_adapter_ids = [str(item).strip() for item in case_row.get("selected_adapter_ids", []) if str(item).strip()]
    selected_adapter_id = selected_adapter_ids[0] if selected_adapter_ids else ""
    exact = (
        str(case_row.get("oracle_policy_outcome", "")).strip() == preferred_policy_outcome
        and selected_adapter_id == adapter_id
        and route_justification == expected_justification
        and bool(case_row.get("preregistered_expectation_satisfied", False))
        and _safe_effect_visible(str(case_row.get("safety_effect", "")).strip())
    )
    admissible = (
        str(case_row.get("oracle_policy_outcome", "")).strip() == preferred_policy_outcome
        and selected_adapter_id == adapter_id
        and bool(route_justification)
        and bool(case_row.get("preregistered_expectation_satisfied", False))
        and _safe_effect_visible(str(case_row.get("safety_effect", "")).strip())
    )
    return {
        "family_id": str(family.get("family_id", "")).strip(),
        "adapter_id": adapter_id,
        "case_id": str(case_row.get("case_id", "")).strip(),
        "case_variant": str(case_row.get("case_variant", "")).strip(),
        "pack_visibility": str(case_row.get("pack_visibility", "")).strip(),
        "oracle_policy_outcome": str(case_row.get("oracle_policy_outcome", "")).strip(),
        "preferred_policy_outcome": preferred_policy_outcome,
        "selected_adapter_id": selected_adapter_id,
        "route_justification": route_justification,
        "expected_route_justification": expected_justification,
        "safety_effect": str(case_row.get("safety_effect", "")).strip(),
        "preregistered_expectation_satisfied": bool(case_row.get("preregistered_expectation_satisfied", False)),
        "bridge_reason_exact": exact,
        "bridge_reason_admissible": admissible,
        "route_consequence_visible": admissible,
    }


def _rows_from_hydrated_payload(lane_b_hydrated_case_packet: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for family in lane_b_hydrated_case_packet.get("hydrated_families", []):
        if not isinstance(family, dict):
            continue
        for case_row in family.get("oracle_case_rows", []):
            if isinstance(case_row, dict):
                rows.append(_row_from_case(family, case_row))
    return rows


def _score_rows(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "row_count": len(rows),
        "action_accuracy": _bool_rate(
            [str(row.get("oracle_policy_outcome", "")).strip() == str(row.get("preferred_policy_outcome", "")).strip() for row in rows]
        ),
        "bridge_reason_exact_accuracy": _bool_rate([bool(row.get("bridge_reason_exact", False)) for row in rows]),
        "bridge_reason_admissible_accuracy": _bool_rate([bool(row.get("bridge_reason_admissible", False)) for row in rows]),
        "route_consequence_visible_rate": _bool_rate([bool(row.get("route_consequence_visible", False)) for row in rows]),
        "selected_adapter_alignment_rate": _bool_rate(
            [str(row.get("selected_adapter_id", "")).strip() == str(row.get("adapter_id", "")).strip() for row in rows]
        ),
    }


def _family_scorecards(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    family_ids = sorted({str(row.get("family_id", "")).strip() for row in rows if str(row.get("family_id", "")).strip()})
    for family_id in family_ids:
        family_rows = [row for row in rows if str(row.get("family_id", "")).strip() == family_id]
        visible = [row for row in family_rows if str(row.get("pack_visibility", "")).strip() == "VISIBLE_TO_AUTHORING"]
        held_out = [row for row in family_rows if str(row.get("pack_visibility", "")).strip() == "HELD_OUT_FOR_GRADING_ONLY"]
        out.append(
            {
                "family_id": family_id,
                "all_case_metrics": _score_rows(family_rows),
                "visible_case_metrics": _score_rows(visible),
                "held_out_case_metrics": _score_rows(held_out),
            }
        )
    return out


def _build_outputs(
    *,
    lane_a_scorecard: Dict[str, Any],
    lane_b_hydrated_case_packet: Dict[str, Any],
    subject_head: str,
) -> Dict[str, Any]:
    row_panel_rows = _rows_from_hydrated_payload(lane_b_hydrated_case_packet)
    overall_metrics = _score_rows(row_panel_rows)
    visible_rows = [row for row in row_panel_rows if str(row.get("pack_visibility", "")).strip() == "VISIBLE_TO_AUTHORING"]
    held_out_rows = [row for row in row_panel_rows if str(row.get("pack_visibility", "")).strip() == "HELD_OUT_FOR_GRADING_ONLY"]
    family_metrics = _family_scorecards(row_panel_rows)

    scorecard = {
        "schema_id": "kt.operator.cohort0_lane_b_family_level_bridge_harness_scorecard.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This scorecard executes Lane B family-level typed bridge+harness scoring on the hydrated live payload only. "
            "It does not reopen Gate D, authorize counted reentry, or open Gate E."
        ),
        "execution_status": "PASS__LANE_B_FAMILY_LEVEL_BRIDGE_HARNESS_EXECUTED",
        "lead_bridge_candidate_id": lane_a_scorecard.get("lead_bridge_candidate_id", lane_a.dual_lane.controller_tranche.LEAD_BRIDGE_ID),
        "hydrated_family_count": int(lane_b_hydrated_case_packet.get("hydrated_family_count", 0)),
        "visible_case_count": len(visible_rows),
        "held_out_case_count": len(held_out_rows),
        "overall_metrics": overall_metrics,
        "visible_case_metrics": _score_rows(visible_rows),
        "held_out_case_metrics": _score_rows(held_out_rows),
        "family_metrics": family_metrics,
        "fixed_harness_global_totals": dict(lane_a_scorecard.get("fixed_harness_global_totals", {})),
        "local_numeric_cost_panel_available": False,
        "family_level_route_consequence_visibility_based_on_safety_surface": True,
        "subject_head": subject_head,
    }

    comparative_packet = {
        "schema_id": "kt.operator.cohort0_cross_lane_bridge_harness_comparative_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This packet compares executed Lane A promoted-survivor evidence against executed Lane B family-level hydrated payload evidence only. "
            "It does not authorize counted reentry, reopen Gate D, or open Gate E."
        ),
        "execution_status": "PASS__CROSS_LANE_COMPARATIVE_PACKET_EMITTED",
        "lane_a_benchmark": {
            "execution_status": str(lane_a_scorecard.get("execution_status", "")).strip(),
            "bridge_reason_exact_accuracy": lane_a_scorecard.get("full_panel_metrics", {}).get("selected_bridge_reason_exact_accuracy", 0.0),
            "bridge_reason_admissible_accuracy": lane_a_scorecard.get("full_panel_metrics", {}).get("selected_bridge_reason_admissible_accuracy", 0.0),
            "local_numeric_cost_panel_available": True,
            "local_wrong_route_cost": lane_a_scorecard.get("full_panel_metrics", {}).get("total_wrong_route_cost", 0.0),
            "local_wrong_static_hold_cost": lane_a_scorecard.get("full_panel_metrics", {}).get("total_wrong_static_hold_cost", 0.0),
        },
        "lane_b_family_level": {
            "execution_status": scorecard["execution_status"],
            "bridge_reason_exact_accuracy": scorecard["overall_metrics"]["bridge_reason_exact_accuracy"],
            "bridge_reason_admissible_accuracy": scorecard["overall_metrics"]["bridge_reason_admissible_accuracy"],
            "local_numeric_cost_panel_available": False,
            "route_consequence_visibility_rate": scorecard["overall_metrics"]["route_consequence_visible_rate"],
            "visible_case_count": scorecard["visible_case_count"],
            "held_out_case_count": scorecard["held_out_case_count"],
            "hydrated_family_count": scorecard["hydrated_family_count"],
        },
        "comparative_read": {
            "lane_a_remains_numeric_benchmark_witness": True,
            "lane_b_now_executed_on_materially_distinct_family_surface": True,
            "lane_b_bridge_quality_near_lane_a_levels": (
                scorecard["overall_metrics"]["bridge_reason_exact_accuracy"]
                >= lane_a_scorecard.get("full_panel_metrics", {}).get("selected_bridge_reason_exact_accuracy", 0.0)
            ),
            "dominance_surface_broadening_visible": scorecard["hydrated_family_count"] >= 2,
            "reentry_prep_eligible_now": False,
            "same_head_counted_reentry_admissible_now": False,
            "gate_d_reopened": False,
            "gate_e_open": False,
        },
        "subject_head": subject_head,
    }

    row_panel = {
        "schema_id": "kt.operator.cohort0_lane_b_family_level_row_panel.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": scorecard["claim_boundary"],
        "rows": row_panel_rows,
        "subject_head": subject_head,
    }

    receipt = {
        "schema_id": "kt.operator.cohort0_lane_b_family_level_execution_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This receipt records Lane B family-level bridge+harness execution on hydrated payload only. "
            "It does not authorize counted reentry, reopen Gate D, or open Gate E."
        ),
        "execution_status": "PASS__LANE_B_FAMILY_LEVEL_BRIDGE_HARNESS_EXECUTED",
        "hydrated_family_count": scorecard["hydrated_family_count"],
        "visible_case_count": scorecard["visible_case_count"],
        "held_out_case_count": scorecard["held_out_case_count"],
        "bridge_quality_near_lane_a_levels": comparative_packet["comparative_read"]["lane_b_bridge_quality_near_lane_a_levels"],
        "dominance_surface_broadening_visible": comparative_packet["comparative_read"]["dominance_surface_broadening_visible"],
        "local_numeric_cost_panel_available": False,
        "same_head_counted_reentry_admissible_now": False,
        "gate_d_reopened": False,
        "gate_e_open": False,
        "next_lawful_move": "USE_CROSS_LANE_COMPARATIVE_PACKET_FOR_NEXT_DUAL_LANE_DECISION__NO_REENTRY_LANGUAGE",
        "subject_head": subject_head,
    }
    return {
        "row_panel": row_panel,
        "scorecard": scorecard,
        "comparative_packet": comparative_packet,
        "receipt": receipt,
    }


def _build_report(*, scorecard: Dict[str, Any], comparative_packet: Dict[str, Any], receipt: Dict[str, Any]) -> str:
    family_lines = "\n".join(
        f"- `{item.get('family_id', '')}`: exact `{item.get('all_case_metrics', {}).get('bridge_reason_exact_accuracy', 0.0)}`, admissible `{item.get('all_case_metrics', {}).get('bridge_reason_admissible_accuracy', 0.0)}`"
        for item in scorecard.get("family_metrics", [])
    )
    lane_a = dict(comparative_packet.get("lane_a_benchmark", {}))
    lane_b = dict(comparative_packet.get("lane_b_family_level", {}))
    compare = dict(comparative_packet.get("comparative_read", {}))
    return (
        "# Cohort0 Lane B Family-Level Execution Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Hydrated family count: `{receipt.get('hydrated_family_count', 0)}`\n"
        f"- Visible case count: `{receipt.get('visible_case_count', 0)}`\n"
        f"- Held-out case count: `{receipt.get('held_out_case_count', 0)}`\n"
        f"- Bridge quality near Lane A levels: `{receipt.get('bridge_quality_near_lane_a_levels', False)}`\n"
        f"- Dominance surface broadening visible: `{receipt.get('dominance_surface_broadening_visible', False)}`\n"
        f"- Local numeric cost panel available: `{receipt.get('local_numeric_cost_panel_available', False)}`\n"
        f"- Counted reentry admissible now: `{receipt.get('same_head_counted_reentry_admissible_now', True)}`\n"
        f"- Gate D reopened: `{receipt.get('gate_d_reopened', True)}`\n"
        f"- Gate E open: `{receipt.get('gate_e_open', True)}`\n"
        f"- Next lawful move: `{receipt.get('next_lawful_move', '')}`\n\n"
        "## Lane B Overall Metrics\n"
        f"- Action accuracy: `{scorecard.get('overall_metrics', {}).get('action_accuracy', 0.0)}`\n"
        f"- Bridge reason exact: `{scorecard.get('overall_metrics', {}).get('bridge_reason_exact_accuracy', 0.0)}`\n"
        f"- Bridge reason admissible: `{scorecard.get('overall_metrics', {}).get('bridge_reason_admissible_accuracy', 0.0)}`\n"
        f"- Route consequence visibility: `{scorecard.get('overall_metrics', {}).get('route_consequence_visible_rate', 0.0)}`\n\n"
        "## Per Family\n"
        f"{family_lines}\n\n"
        "## Cross-Lane Read\n"
        f"- Lane A bridge exact: `{lane_a.get('bridge_reason_exact_accuracy', 0.0)}`\n"
        f"- Lane A local wrong-route cost: `{lane_a.get('local_wrong_route_cost', 0.0)}`\n"
        f"- Lane B bridge exact: `{lane_b.get('bridge_reason_exact_accuracy', 0.0)}`\n"
        f"- Lane B route consequence visibility: `{lane_b.get('route_consequence_visibility_rate', 0.0)}`\n"
        f"- Lane A remains numeric benchmark witness: `{compare.get('lane_a_remains_numeric_benchmark_witness', False)}`\n"
        f"- Lane B executed on materially distinct family surface: `{compare.get('lane_b_now_executed_on_materially_distinct_family_surface', False)}`\n"
        f"- Reentry prep eligible now: `{compare.get('reentry_prep_eligible_now', False)}`\n"
    )


def run(
    *,
    verdict_packet_path: Path,
    reentry_block_path: Path,
    lane_a_receipt_path: Path,
    lane_a_scorecard_path: Path,
    lane_b_hydration_receipt_path: Path,
    lane_b_hydrated_case_packet_path: Path,
    reports_root: Path,
) -> Dict[str, Any]:
    verdict_packet = _load_json_required(verdict_packet_path, label="hardened ceiling verdict packet")
    reentry_block = _load_json_required(reentry_block_path, label="gate d reentry block contract")
    lane_a_receipt = _load_json_required(lane_a_receipt_path, label="lane a promoted-survivor execution receipt")
    lane_a_scorecard = _load_json_required(lane_a_scorecard_path, label="lane a promoted-survivor scorecard")
    lane_b_hydration_receipt = _load_json_required(
        lane_b_hydration_receipt_path, label="lane b hydration receipt"
    )
    lane_b_hydrated_case_packet = _load_json_required(
        lane_b_hydrated_case_packet_path, label="lane b hydrated case packet"
    )

    _validate_inputs(
        verdict_packet=verdict_packet,
        reentry_block=reentry_block,
        lane_a_receipt=lane_a_receipt,
        lane_a_scorecard=lane_a_scorecard,
        lane_b_hydration_receipt=lane_b_hydration_receipt,
        lane_b_hydrated_case_packet=lane_b_hydrated_case_packet,
    )
    subject_head = _require_same_subject_head(
        (
            verdict_packet,
            reentry_block,
            lane_a_receipt,
            lane_a_scorecard,
            lane_b_hydration_receipt,
            lane_b_hydrated_case_packet,
        )
    )

    outputs = _build_outputs(
        lane_a_scorecard=lane_a_scorecard,
        lane_b_hydrated_case_packet=lane_b_hydrated_case_packet,
        subject_head=subject_head,
    )

    reports_root.mkdir(parents=True, exist_ok=True)
    row_panel_path = reports_root / OUTPUT_ROW_PANEL
    scorecard_path = reports_root / OUTPUT_SCORECARD
    comparative_packet_path = reports_root / OUTPUT_COMPARATIVE_PACKET
    receipt_path = reports_root / OUTPUT_RECEIPT
    report_path = reports_root / OUTPUT_REPORT

    write_json_stable(row_panel_path, outputs["row_panel"])
    write_json_stable(scorecard_path, outputs["scorecard"])
    write_json_stable(comparative_packet_path, outputs["comparative_packet"])
    write_json_stable(receipt_path, outputs["receipt"])
    _write_text(
        report_path,
        _build_report(
            scorecard=outputs["scorecard"],
            comparative_packet=outputs["comparative_packet"],
            receipt=outputs["receipt"],
        ),
    )

    return {
        "status": "PASS",
        "execution_status": outputs["receipt"]["execution_status"],
        "bridge_quality_near_lane_a_levels": outputs["receipt"]["bridge_quality_near_lane_a_levels"],
        "dominance_surface_broadening_visible": outputs["receipt"]["dominance_surface_broadening_visible"],
        "hydrated_family_count": outputs["receipt"]["hydrated_family_count"],
        "output_count": 5,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Execute Lane B family-level typed bridge+harness scoring on the hydrated payload."
    )
    parser.add_argument("--verdict-packet", default=DEFAULT_VERDICT_PACKET_REL)
    parser.add_argument("--reentry-block", default=DEFAULT_REENTRY_BLOCK_REL)
    parser.add_argument("--lane-a-receipt", default=DEFAULT_LANE_A_RECEIPT_REL)
    parser.add_argument("--lane-a-scorecard", default=DEFAULT_LANE_A_SCORECARD_REL)
    parser.add_argument("--lane-b-hydration-receipt", default=DEFAULT_LANE_B_HYDRATION_RECEIPT_REL)
    parser.add_argument("--lane-b-hydrated-case-packet", default=DEFAULT_LANE_B_HYDRATED_CASE_PACKET_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    args = parser.parse_args(argv)

    root = repo_root()
    result = run(
        verdict_packet_path=_resolve(root, args.verdict_packet),
        reentry_block_path=_resolve(root, args.reentry_block),
        lane_a_receipt_path=_resolve(root, args.lane_a_receipt),
        lane_a_scorecard_path=_resolve(root, args.lane_a_scorecard),
        lane_b_hydration_receipt_path=_resolve(root, args.lane_b_hydration_receipt),
        lane_b_hydrated_case_packet_path=_resolve(root, args.lane_b_hydrated_case_packet),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in (
        "status",
        "execution_status",
        "bridge_quality_near_lane_a_levels",
        "dominance_surface_broadening_visible",
        "hydrated_family_count",
        "output_count",
        "receipt_path",
        "subject_head",
    ):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
