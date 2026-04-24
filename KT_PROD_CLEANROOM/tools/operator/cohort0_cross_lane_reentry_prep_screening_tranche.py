from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_dual_lane_first_execution_tranche as dual_lane
from tools.operator import cohort0_lane_a_promoted_survivor_execution_tranche as lane_a_exec
from tools.operator import cohort0_lane_b_family_level_bridge_harness_tranche as lane_b_exec
from tools.operator import cohort0_first_successor_evidence_setup_tranche as setup_tranche
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_VERDICT_PACKET_REL = setup_tranche.DEFAULT_VERDICT_PACKET_REL
DEFAULT_REENTRY_BLOCK_REL = setup_tranche.DEFAULT_REENTRY_BLOCK_REL
DEFAULT_LANE_A_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{lane_a_exec.OUTPUT_RECEIPT}"
DEFAULT_LANE_A_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{lane_a_exec.OUTPUT_SCORECARD}"
DEFAULT_LANE_B_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{lane_b_exec.OUTPUT_RECEIPT}"
DEFAULT_LANE_B_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{lane_b_exec.OUTPUT_SCORECARD}"
DEFAULT_CROSS_LANE_COMPARATIVE_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{lane_b_exec.OUTPUT_COMPARATIVE_PACKET}"
DEFAULT_DUAL_LANE_A_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{dual_lane.OUTPUT_LANE_A_SCORECARD}"
DEFAULT_DUAL_LANE_B_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{dual_lane.OUTPUT_LANE_B_SCORECARD}"
DEFAULT_THIRD_ROW_PANEL_REL = f"KT_PROD_CLEANROOM/reports/{dual_lane.third_wave.OUTPUT_ROW_PANEL}"
DEFAULT_ROUTE_BEARING_MANIFEST_REL = dual_lane.DEFAULT_ROUTE_BEARING_MANIFEST_REL
DEFAULT_ROUTE_BEARING_INDEX_REL = dual_lane.DEFAULT_ROUTE_BEARING_INDEX_REL
DEFAULT_ORACLE_LOCAL_EVAL_PACKET_REL = "KT_PROD_CLEANROOM/reports/oracle_router_local_eval_packet.json"
DEFAULT_SINGLE_AXIS_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/single_axis_crucible_input_manifest.json"
DEFAULT_TARGETED_HYPERTRAINING_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/cohort0_targeted_hypertraining_stage_input_manifest.json"
DEFAULT_REPORTS_ROOT_REL = setup_tranche.DEFAULT_REPORTS_ROOT_REL

OUTPUT_LANE_A_RESERVE_SCORECARD = "cohort0_lane_a_reserve_challenge_scorecard.json"
OUTPUT_LANE_B_RESERVE_SCORECARD = "cohort0_lane_b_reserve_challenge_scorecard.json"
OUTPUT_SCREENING_PACKET = "cohort0_cross_lane_reentry_prep_screening_packet.json"
OUTPUT_RECEIPT = "cohort0_cross_lane_reentry_prep_screening_receipt.json"
OUTPUT_REPORT = "COHORT0_CROSS_LANE_REENTRY_PREP_SCREENING_REPORT.md"


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
        raise RuntimeError("FAIL_CLOSED: cross-lane reentry-prep screening requires one same-head authority line")
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
    lane_b_receipt: Dict[str, Any],
    lane_b_scorecard: Dict[str, Any],
    cross_lane_packet: Dict[str, Any],
    dual_lane_a_scorecard: Dict[str, Any],
    dual_lane_b_scorecard: Dict[str, Any],
    third_row_panel: Dict[str, Any],
    route_bearing_manifest: Dict[str, Any],
    route_bearing_index: Dict[str, Any],
    oracle_local_eval_packet: Dict[str, Any],
    single_axis_manifest: Dict[str, Any],
    targeted_hypertraining_manifest: Dict[str, Any],
) -> None:
    for payload, label in (
        (verdict_packet, "hardened ceiling verdict packet"),
        (reentry_block, "gate d reentry block contract"),
        (lane_a_receipt, "lane a promoted-survivor receipt"),
        (lane_a_scorecard, "lane a promoted-survivor scorecard"),
        (lane_b_receipt, "lane b family-level receipt"),
        (lane_b_scorecard, "lane b family-level scorecard"),
        (cross_lane_packet, "cross-lane comparative packet"),
        (dual_lane_a_scorecard, "dual-lane lane a scorecard"),
        (dual_lane_b_scorecard, "dual-lane lane b scorecard"),
        (third_row_panel, "third successor bridge-bound row panel"),
        (route_bearing_manifest, "route-bearing stage pack manifest"),
        (route_bearing_index, "route-bearing stage pack index"),
        (oracle_local_eval_packet, "oracle router local eval packet"),
        (single_axis_manifest, "single-axis crucible input manifest"),
        (targeted_hypertraining_manifest, "targeted hypertraining stage input manifest"),
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
        raise RuntimeError("FAIL_CLOSED: Lane A promoted-survivor execution must exist")
    if str(lane_b_receipt.get("execution_status", "")).strip() != "PASS__LANE_B_FAMILY_LEVEL_BRIDGE_HARNESS_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: Lane B family-level execution must exist")
    if str(cross_lane_packet.get("execution_status", "")).strip() != "PASS__CROSS_LANE_COMPARATIVE_PACKET_EMITTED":
        raise RuntimeError("FAIL_CLOSED: cross-lane comparative packet must exist")

    for receipt in (lane_a_receipt, lane_b_receipt):
        if bool(receipt.get("same_head_counted_reentry_admissible_now", True)):
            raise RuntimeError("FAIL_CLOSED: counted reentry must remain blocked entering reentry-prep screening")
        if bool(receipt.get("gate_d_reopened", True)):
            raise RuntimeError("FAIL_CLOSED: Gate D must remain closed entering reentry-prep screening")
        if bool(receipt.get("gate_e_open", True)):
            raise RuntimeError("FAIL_CLOSED: Gate E must remain closed entering reentry-prep screening")

    comparative_read = dict(cross_lane_packet.get("comparative_read", {}))
    if not bool(comparative_read.get("lane_a_remains_numeric_benchmark_witness", False)):
        raise RuntimeError("FAIL_CLOSED: Lane A benchmark witness status must remain true")
    if not bool(comparative_read.get("lane_b_now_executed_on_materially_distinct_family_surface", False)):
        raise RuntimeError("FAIL_CLOSED: Lane B materially distinct execution must remain true")

    if not isinstance(dual_lane_a_scorecard.get("reserves"), list):
        raise RuntimeError("FAIL_CLOSED: Lane A scorecard must expose reserves")
    if not isinstance(dual_lane_b_scorecard.get("reserves"), list):
        raise RuntimeError("FAIL_CLOSED: Lane B scorecard must expose reserves")


def _select_lane_a_reserve(dual_lane_a_scorecard: Dict[str, Any]) -> Dict[str, Any]:
    reserves = {
        str(item.get("item_id", "")).strip()
        for item in dual_lane_a_scorecard.get("reserves", [])
        if isinstance(item, dict) and str(item.get("item_id", "")).strip()
    }
    preferred: Optional[Dict[str, Any]] = None
    fallback: Optional[Dict[str, Any]] = None
    for candidate in dual_lane_a_scorecard.get("candidates", []):
        if not isinstance(candidate, dict):
            continue
        candidate_id = str(candidate.get("mutation_candidate_id", "")).strip()
        if candidate_id not in reserves:
            continue
        if fallback is None:
            fallback = candidate
        if str(candidate.get("variant_type", "")).strip() == "core":
            preferred = candidate
            break
    selected = preferred or fallback
    if not isinstance(selected, dict):
        raise RuntimeError("FAIL_CLOSED: unable to select Lane A reserve challenge")
    return selected


def _select_lane_b_reserve(dual_lane_b_scorecard: Dict[str, Any]) -> Dict[str, Any]:
    reserve_ids = [
        str(item.get("item_id", "")).strip()
        for item in dual_lane_b_scorecard.get("reserves", [])
        if isinstance(item, dict) and str(item.get("item_id", "")).strip()
    ]
    if not reserve_ids:
        raise RuntimeError("FAIL_CLOSED: unable to select Lane B reserve challenge")
    target = reserve_ids[0]
    for prospect in dual_lane_b_scorecard.get("prospects", []):
        if isinstance(prospect, dict) and str(prospect.get("family_id", "")).strip() == target:
            return prospect
    raise RuntimeError("FAIL_CLOSED: Lane B reserve prospect not found in prospect list")


def _rows_by_case_id(third_row_panel: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {
        str(row.get("case_id", "")).strip(): row
        for row in third_row_panel.get("rows", [])
        if isinstance(row, dict) and str(row.get("case_id", "")).strip()
    }


def _lane_a_reserve_scorecard(selected_reserve: Dict[str, Any], third_row_panel: Dict[str, Any]) -> Dict[str, Any]:
    rows_by_case = _rows_by_case_id(third_row_panel)
    case_id = str(selected_reserve.get("source_case_id", "")).strip()
    if not case_id:
        raise RuntimeError("FAIL_CLOSED: Lane A reserve challenge missing source_case_id")
    primary_row = dict(rows_by_case.get(case_id, {}))
    if not primary_row:
        raise RuntimeError(f"FAIL_CLOSED: missing Lane A reserve row: {case_id}")
    masked_row = dict(rows_by_case.get(f"{case_id}__MASKED", {}))
    rows = [primary_row]
    if masked_row:
        rows.append(masked_row)
    return {
        "reserve_item_id": str(selected_reserve.get("mutation_candidate_id", "")).strip(),
        "source_case_id": case_id,
        "source_family_id": str(selected_reserve.get("source_family_id", "")).strip(),
        "source_legacy_family_id": str(selected_reserve.get("source_legacy_family_id", "")).strip(),
        "row_count": len(rows),
        "masked_companion_present": bool(masked_row),
        "baseline_reason_exact_accuracy": _bool_rate([bool(row.get("baseline_reason_exact", False)) for row in rows]),
        "baseline_reason_admissible_accuracy": _bool_rate([bool(row.get("baseline_reason_admissible", False)) for row in rows]),
        "selected_bridge_reason_exact_accuracy": _bool_rate(
            [bool(row.get("selected_bridge_reason_exact", False)) for row in rows]
        ),
        "selected_bridge_reason_admissible_accuracy": _bool_rate(
            [bool(row.get("selected_bridge_reason_admissible", False)) for row in rows]
        ),
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
        "total_wrong_route_cost": _round_float(sum(float(row.get("wrong_route_cost", 0.0)) for row in rows)),
        "total_wrong_static_hold_cost": _round_float(sum(float(row.get("wrong_static_hold_cost", 0.0)) for row in rows)),
        "mean_observed_route_margin": _round_float(
            sum(float(row.get("observed_route_margin", 0.0)) for row in rows) / max(1, len(rows))
        ),
        "bridge_hold": all(bool(row.get("selected_bridge_reason_exact", False)) for row in rows)
        and all(bool(row.get("selected_bridge_reason_admissible", False)) for row in rows),
    }


def _index_by_family(rows: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        family_id = str(row.get("family_id", "")).strip()
        if family_id:
            out[family_id] = row
    return out


def _family_rows(rows: Sequence[Dict[str, Any]], family_id: str) -> List[Dict[str, Any]]:
    return [
        dict(row)
        for row in rows
        if isinstance(row, dict) and str(row.get("family_id", "")).strip() == family_id
    ]


def _expected_route_justification(*, adapter_id: str, alpha_liability: str) -> str:
    liability = str(alpha_liability).strip()
    if liability and not liability.endswith("."):
        liability = f"{liability}."
    return f"Route to {adapter_id} because {liability}".strip()


def _lane_b_reserve_scorecard(
    selected_reserve: Dict[str, Any],
    route_bearing_manifest: Dict[str, Any],
    route_bearing_index: Dict[str, Any],
    oracle_local_eval_packet: Dict[str, Any],
    single_axis_manifest: Dict[str, Any],
    targeted_hypertraining_manifest: Dict[str, Any],
) -> Dict[str, Any]:
    family_id = str(selected_reserve.get("family_id", "")).strip()
    if not family_id:
        raise RuntimeError("FAIL_CLOSED: Lane B reserve challenge missing family_id")

    manifest_row = dict(_index_by_family(route_bearing_manifest.get("family_rows", [])).get(family_id, {}))
    single_axis_row = dict(_index_by_family(single_axis_manifest.get("family_rows", [])).get(family_id, {}))
    targeted_row = dict(_index_by_family(targeted_hypertraining_manifest.get("dataset_rows", [])).get(family_id, {}))
    if not manifest_row or not single_axis_row or not targeted_row:
        raise RuntimeError(f"FAIL_CLOSED: incomplete Lane B reserve source chain for family {family_id}")

    oracle_rows = _family_rows(oracle_local_eval_packet.get("case_results", []), family_id)
    index_rows = _family_rows(route_bearing_index.get("rows", []), family_id)
    if not oracle_rows or not index_rows:
        raise RuntimeError(f"FAIL_CLOSED: missing Lane B reserve case rows for family {family_id}")

    adapter_id = str(targeted_row.get("adapter_id", "")).strip()
    preferred_policy_outcome = str(single_axis_row.get("preferred_policy_outcome", "")).strip()
    expected_justification = _expected_route_justification(
        adapter_id=adapter_id,
        alpha_liability=str(manifest_row.get("alpha_liability", "")).strip(),
    )

    scored_rows: List[Dict[str, Any]] = []
    for row in oracle_rows:
        selected_adapter_ids = [str(item).strip() for item in row.get("selected_adapter_ids", []) if str(item).strip()]
        selected_adapter_id = selected_adapter_ids[0] if selected_adapter_ids else ""
        route_justification = str(row.get("route_justification", "")).strip()
        exact = (
            str(row.get("oracle_policy_outcome", "")).strip() == preferred_policy_outcome
            and selected_adapter_id == adapter_id
            and route_justification == expected_justification
            and bool(row.get("preregistered_expectation_satisfied", False))
            and str(row.get("safety_effect", "")).strip() == "ROUTE_EXPECTED_TO_REDUCE_ALPHA_LIABILITY"
        )
        admissible = (
            str(row.get("oracle_policy_outcome", "")).strip() == preferred_policy_outcome
            and selected_adapter_id == adapter_id
            and bool(route_justification)
            and bool(row.get("preregistered_expectation_satisfied", False))
            and str(row.get("safety_effect", "")).strip() == "ROUTE_EXPECTED_TO_REDUCE_ALPHA_LIABILITY"
        )
        scored_rows.append(
            {
                "case_id": str(row.get("case_id", "")).strip(),
                "case_variant": str(row.get("case_variant", "")).strip(),
                "pack_visibility": str(row.get("pack_visibility", "")).strip(),
                "bridge_reason_exact": exact,
                "bridge_reason_admissible": admissible,
                "selected_adapter_alignment": selected_adapter_id == adapter_id,
                "route_consequence_visible": admissible,
            }
        )

    visible_rows = [row for row in scored_rows if str(row.get("pack_visibility", "")).strip() == "VISIBLE_TO_AUTHORING"]
    held_out_rows = [row for row in scored_rows if str(row.get("pack_visibility", "")).strip() == "HELD_OUT_FOR_GRADING_ONLY"]
    return {
        "reserve_item_id": family_id,
        "visible_case_count": len(visible_rows),
        "held_out_case_count": len(held_out_rows),
        "indexed_case_count": len(index_rows),
        "all_case_metrics": {
            "bridge_reason_exact_accuracy": _bool_rate([bool(row.get("bridge_reason_exact", False)) for row in scored_rows]),
            "bridge_reason_admissible_accuracy": _bool_rate(
                [bool(row.get("bridge_reason_admissible", False)) for row in scored_rows]
            ),
            "selected_adapter_alignment_rate": _bool_rate(
                [bool(row.get("selected_adapter_alignment", False)) for row in scored_rows]
            ),
            "route_consequence_visible_rate": _bool_rate(
                [bool(row.get("route_consequence_visible", False)) for row in scored_rows]
            ),
            "row_count": len(scored_rows),
        },
        "visible_case_metrics": {
            "bridge_reason_exact_accuracy": _bool_rate([bool(row.get("bridge_reason_exact", False)) for row in visible_rows]),
            "bridge_reason_admissible_accuracy": _bool_rate(
                [bool(row.get("bridge_reason_admissible", False)) for row in visible_rows]
            ),
            "selected_adapter_alignment_rate": _bool_rate(
                [bool(row.get("selected_adapter_alignment", False)) for row in visible_rows]
            ),
            "route_consequence_visible_rate": _bool_rate(
                [bool(row.get("route_consequence_visible", False)) for row in visible_rows]
            ),
            "row_count": len(visible_rows),
        },
        "held_out_case_metrics": {
            "bridge_reason_exact_accuracy": _bool_rate([bool(row.get("bridge_reason_exact", False)) for row in held_out_rows]),
            "bridge_reason_admissible_accuracy": _bool_rate(
                [bool(row.get("bridge_reason_admissible", False)) for row in held_out_rows]
            ),
            "selected_adapter_alignment_rate": _bool_rate(
                [bool(row.get("selected_adapter_alignment", False)) for row in held_out_rows]
            ),
            "route_consequence_visible_rate": _bool_rate(
                [bool(row.get("route_consequence_visible", False)) for row in held_out_rows]
            ),
            "row_count": len(held_out_rows),
        },
    }


def _build_outputs(
    *,
    lane_a_scorecard: Dict[str, Any],
    lane_b_scorecard: Dict[str, Any],
    cross_lane_packet: Dict[str, Any],
    lane_a_reserve_scorecard: Dict[str, Any],
    lane_b_reserve_scorecard: Dict[str, Any],
    subject_head: str,
) -> Dict[str, Any]:
    lane_a_full_metrics = dict(lane_a_scorecard.get("full_panel_metrics", {}))
    lane_b_overall_metrics = dict(lane_b_scorecard.get("overall_metrics", {}))
    comparative_read = dict(cross_lane_packet.get("comparative_read", {}))

    reserve_challenges_pass = (
        bool(lane_a_reserve_scorecard.get("bridge_hold", False))
        and float(lane_b_reserve_scorecard.get("all_case_metrics", {}).get("bridge_reason_exact_accuracy", 0.0)) >= 1.0
        and float(lane_b_reserve_scorecard.get("all_case_metrics", {}).get("route_consequence_visible_rate", 0.0)) >= 1.0
    )

    successor_reentry_prep_packet_authorized = (
        float(lane_a_full_metrics.get("selected_bridge_reason_exact_accuracy", 0.0)) >= 1.0
        and float(lane_b_overall_metrics.get("bridge_reason_exact_accuracy", 0.0)) >= 1.0
        and bool(comparative_read.get("dominance_surface_broadening_visible", False))
        and bool(comparative_read.get("lane_b_bridge_quality_near_lane_a_levels", False))
        and reserve_challenges_pass
    )

    screening_packet = {
        "schema_id": "kt.operator.cohort0_cross_lane_reentry_prep_screening_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This packet screens whether the current dual-lane bundle is strong enough to authorize a successor reentry-prep packet only. "
            "It does not authorize counted reentry, reopen Gate D, or open Gate E."
        ),
        "execution_status": "PASS__CROSS_LANE_REENTRY_PREP_SCREEN_EXECUTED",
        "lane_a_benchmark_exact_accuracy": lane_a_full_metrics.get("selected_bridge_reason_exact_accuracy", 0.0),
        "lane_b_family_exact_accuracy": lane_b_overall_metrics.get("bridge_reason_exact_accuracy", 0.0),
        "cross_lane_dominance_broadening_visible": bool(comparative_read.get("dominance_surface_broadening_visible", False)),
        "lane_a_reserve_challenge": lane_a_reserve_scorecard,
        "lane_b_reserve_challenge": lane_b_reserve_scorecard,
        "reserve_challenges_pass": reserve_challenges_pass,
        "successor_reentry_prep_packet_authorized": successor_reentry_prep_packet_authorized,
        "same_head_counted_reentry_admissible_now": False,
        "gate_d_reopened": False,
        "gate_e_open": False,
        "subject_head": subject_head,
    }

    receipt = {
        "schema_id": "kt.operator.cohort0_cross_lane_reentry_prep_screening_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": screening_packet["claim_boundary"],
        "execution_status": "PASS__CROSS_LANE_REENTRY_PREP_SCREEN_EXECUTED",
        "reserve_challenges_pass": reserve_challenges_pass,
        "successor_reentry_prep_packet_authorized": successor_reentry_prep_packet_authorized,
        "same_head_counted_reentry_admissible_now": False,
        "gate_d_reopened": False,
        "gate_e_open": False,
        "next_lawful_move": (
            "AUTHOR_SUCCESSOR_REENTRY_PREP_PACKET__STRICTLY_PRE_GATE_D"
            if successor_reentry_prep_packet_authorized
            else "RUN_ADDITIONAL_RESERVE_OR_ADVERSARIAL_EXTENSION_BEFORE_REENTRY_PREP"
        ),
        "subject_head": subject_head,
    }

    lane_a_reserve_payload = {
        "schema_id": "kt.operator.cohort0_lane_a_reserve_challenge_scorecard.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": "PASS__LANE_A_RESERVE_CHALLENGE_SCORED",
        **lane_a_reserve_scorecard,
        "subject_head": subject_head,
    }
    lane_b_reserve_payload = {
        "schema_id": "kt.operator.cohort0_lane_b_reserve_challenge_scorecard.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": "PASS__LANE_B_RESERVE_CHALLENGE_SCORED",
        **lane_b_reserve_scorecard,
        "subject_head": subject_head,
    }
    return {
        "lane_a_reserve_scorecard": lane_a_reserve_payload,
        "lane_b_reserve_scorecard": lane_b_reserve_payload,
        "screening_packet": screening_packet,
        "receipt": receipt,
    }


def _build_report(
    *,
    lane_a_reserve_scorecard: Dict[str, Any],
    lane_b_reserve_scorecard: Dict[str, Any],
    screening_packet: Dict[str, Any],
    receipt: Dict[str, Any],
) -> str:
    return (
        "# Cohort0 Cross-Lane Reentry Prep Screening Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Successor reentry-prep packet authorized: `{receipt.get('successor_reentry_prep_packet_authorized', False)}`\n"
        f"- Reserve challenges pass: `{receipt.get('reserve_challenges_pass', False)}`\n"
        f"- Counted reentry admissible now: `{receipt.get('same_head_counted_reentry_admissible_now', True)}`\n"
        f"- Gate D reopened: `{receipt.get('gate_d_reopened', True)}`\n"
        f"- Gate E open: `{receipt.get('gate_e_open', True)}`\n"
        f"- Next lawful move: `{receipt.get('next_lawful_move', '')}`\n\n"
        "## Lane A Reserve Challenge\n"
        f"- Reserve item: `{lane_a_reserve_scorecard.get('reserve_item_id', '')}`\n"
        f"- Bridge exact: `{lane_a_reserve_scorecard.get('selected_bridge_reason_exact_accuracy', 0.0)}`\n"
        f"- Bridge admissible: `{lane_a_reserve_scorecard.get('selected_bridge_reason_admissible_accuracy', 0.0)}`\n"
        f"- Wrong-route cost: `{lane_a_reserve_scorecard.get('total_wrong_route_cost', 0.0)}`\n\n"
        "## Lane B Reserve Challenge\n"
        f"- Reserve item: `{lane_b_reserve_scorecard.get('reserve_item_id', '')}`\n"
        f"- All-case exact: `{lane_b_reserve_scorecard.get('all_case_metrics', {}).get('bridge_reason_exact_accuracy', 0.0)}`\n"
        f"- All-case admissible: `{lane_b_reserve_scorecard.get('all_case_metrics', {}).get('bridge_reason_admissible_accuracy', 0.0)}`\n"
        f"- Route consequence visibility: `{lane_b_reserve_scorecard.get('all_case_metrics', {}).get('route_consequence_visible_rate', 0.0)}`\n\n"
        "## Screening Decision\n"
        f"- Dominance broadening visible: `{screening_packet.get('cross_lane_dominance_broadening_visible', False)}`\n"
        f"- Lane A benchmark exact: `{screening_packet.get('lane_a_benchmark_exact_accuracy', 0.0)}`\n"
        f"- Lane B family exact: `{screening_packet.get('lane_b_family_exact_accuracy', 0.0)}`\n"
    )


def run(
    *,
    verdict_packet_path: Path,
    reentry_block_path: Path,
    lane_a_receipt_path: Path,
    lane_a_scorecard_path: Path,
    lane_b_receipt_path: Path,
    lane_b_scorecard_path: Path,
    cross_lane_packet_path: Path,
    dual_lane_a_scorecard_path: Path,
    dual_lane_b_scorecard_path: Path,
    third_row_panel_path: Path,
    route_bearing_manifest_path: Path,
    route_bearing_index_path: Path,
    oracle_local_eval_packet_path: Path,
    single_axis_manifest_path: Path,
    targeted_hypertraining_manifest_path: Path,
    reports_root: Path,
) -> Dict[str, Any]:
    verdict_packet = _load_json_required(verdict_packet_path, label="hardened ceiling verdict packet")
    reentry_block = _load_json_required(reentry_block_path, label="gate d reentry block contract")
    lane_a_receipt = _load_json_required(lane_a_receipt_path, label="lane a promoted-survivor receipt")
    lane_a_scorecard = _load_json_required(lane_a_scorecard_path, label="lane a promoted-survivor scorecard")
    lane_b_receipt = _load_json_required(lane_b_receipt_path, label="lane b family-level receipt")
    lane_b_scorecard = _load_json_required(lane_b_scorecard_path, label="lane b family-level scorecard")
    cross_lane_packet = _load_json_required(cross_lane_packet_path, label="cross-lane comparative packet")
    dual_lane_a_scorecard = _load_json_required(dual_lane_a_scorecard_path, label="dual-lane lane a scorecard")
    dual_lane_b_scorecard = _load_json_required(dual_lane_b_scorecard_path, label="dual-lane lane b scorecard")
    third_row_panel = _load_json_required(third_row_panel_path, label="third successor bridge-bound row panel")
    route_bearing_manifest = _load_json_required(route_bearing_manifest_path, label="route-bearing stage pack manifest")
    route_bearing_index = _load_json_required(route_bearing_index_path, label="route-bearing stage pack index")
    oracle_local_eval_packet = _load_json_required(
        oracle_local_eval_packet_path, label="oracle router local eval packet"
    )
    single_axis_manifest = _load_json_required(single_axis_manifest_path, label="single-axis crucible input manifest")
    targeted_hypertraining_manifest = _load_json_required(
        targeted_hypertraining_manifest_path, label="targeted hypertraining stage input manifest"
    )

    _validate_inputs(
        verdict_packet=verdict_packet,
        reentry_block=reentry_block,
        lane_a_receipt=lane_a_receipt,
        lane_a_scorecard=lane_a_scorecard,
        lane_b_receipt=lane_b_receipt,
        lane_b_scorecard=lane_b_scorecard,
        cross_lane_packet=cross_lane_packet,
        dual_lane_a_scorecard=dual_lane_a_scorecard,
        dual_lane_b_scorecard=dual_lane_b_scorecard,
        third_row_panel=third_row_panel,
        route_bearing_manifest=route_bearing_manifest,
        route_bearing_index=route_bearing_index,
        oracle_local_eval_packet=oracle_local_eval_packet,
        single_axis_manifest=single_axis_manifest,
        targeted_hypertraining_manifest=targeted_hypertraining_manifest,
    )
    subject_head = _require_same_subject_head(
        (
            verdict_packet,
            reentry_block,
            lane_a_receipt,
            lane_a_scorecard,
            lane_b_receipt,
            lane_b_scorecard,
            cross_lane_packet,
            dual_lane_a_scorecard,
            dual_lane_b_scorecard,
            third_row_panel,
            route_bearing_manifest,
            route_bearing_index,
            oracle_local_eval_packet,
            single_axis_manifest,
            targeted_hypertraining_manifest,
        )
    )

    lane_a_reserve = _select_lane_a_reserve(dual_lane_a_scorecard)
    lane_b_reserve = _select_lane_b_reserve(dual_lane_b_scorecard)

    lane_a_reserve_scorecard = _lane_a_reserve_scorecard(lane_a_reserve, third_row_panel)
    lane_b_reserve_scorecard = _lane_b_reserve_scorecard(
        lane_b_reserve,
        route_bearing_manifest,
        route_bearing_index,
        oracle_local_eval_packet,
        single_axis_manifest,
        targeted_hypertraining_manifest,
    )

    outputs = _build_outputs(
        lane_a_scorecard=lane_a_scorecard,
        lane_b_scorecard=lane_b_scorecard,
        cross_lane_packet=cross_lane_packet,
        lane_a_reserve_scorecard=lane_a_reserve_scorecard,
        lane_b_reserve_scorecard=lane_b_reserve_scorecard,
        subject_head=subject_head,
    )

    reports_root.mkdir(parents=True, exist_ok=True)
    lane_a_reserve_path = reports_root / OUTPUT_LANE_A_RESERVE_SCORECARD
    lane_b_reserve_path = reports_root / OUTPUT_LANE_B_RESERVE_SCORECARD
    screening_packet_path = reports_root / OUTPUT_SCREENING_PACKET
    receipt_path = reports_root / OUTPUT_RECEIPT
    report_path = reports_root / OUTPUT_REPORT

    write_json_stable(lane_a_reserve_path, outputs["lane_a_reserve_scorecard"])
    write_json_stable(lane_b_reserve_path, outputs["lane_b_reserve_scorecard"])
    write_json_stable(screening_packet_path, outputs["screening_packet"])
    write_json_stable(receipt_path, outputs["receipt"])
    _write_text(
        report_path,
        _build_report(
            lane_a_reserve_scorecard=outputs["lane_a_reserve_scorecard"],
            lane_b_reserve_scorecard=outputs["lane_b_reserve_scorecard"],
            screening_packet=outputs["screening_packet"],
            receipt=outputs["receipt"],
        ),
    )

    return {
        "status": "PASS",
        "execution_status": outputs["receipt"]["execution_status"],
        "successor_reentry_prep_packet_authorized": outputs["receipt"]["successor_reentry_prep_packet_authorized"],
        "reserve_challenges_pass": outputs["receipt"]["reserve_challenges_pass"],
        "output_count": 5,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Screen whether the current cross-lane bundle is strong enough to authorize a successor reentry-prep packet."
    )
    parser.add_argument("--verdict-packet", default=DEFAULT_VERDICT_PACKET_REL)
    parser.add_argument("--reentry-block", default=DEFAULT_REENTRY_BLOCK_REL)
    parser.add_argument("--lane-a-receipt", default=DEFAULT_LANE_A_RECEIPT_REL)
    parser.add_argument("--lane-a-scorecard", default=DEFAULT_LANE_A_SCORECARD_REL)
    parser.add_argument("--lane-b-receipt", default=DEFAULT_LANE_B_RECEIPT_REL)
    parser.add_argument("--lane-b-scorecard", default=DEFAULT_LANE_B_SCORECARD_REL)
    parser.add_argument("--cross-lane-packet", default=DEFAULT_CROSS_LANE_COMPARATIVE_PACKET_REL)
    parser.add_argument("--dual-lane-a-scorecard", default=DEFAULT_DUAL_LANE_A_SCORECARD_REL)
    parser.add_argument("--dual-lane-b-scorecard", default=DEFAULT_DUAL_LANE_B_SCORECARD_REL)
    parser.add_argument("--third-row-panel", default=DEFAULT_THIRD_ROW_PANEL_REL)
    parser.add_argument("--route-bearing-manifest", default=DEFAULT_ROUTE_BEARING_MANIFEST_REL)
    parser.add_argument("--route-bearing-index", default=DEFAULT_ROUTE_BEARING_INDEX_REL)
    parser.add_argument("--oracle-local-eval-packet", default=DEFAULT_ORACLE_LOCAL_EVAL_PACKET_REL)
    parser.add_argument("--single-axis-manifest", default=DEFAULT_SINGLE_AXIS_MANIFEST_REL)
    parser.add_argument("--targeted-hypertraining-manifest", default=DEFAULT_TARGETED_HYPERTRAINING_MANIFEST_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    args = parser.parse_args(argv)

    root = repo_root()
    result = run(
        verdict_packet_path=_resolve(root, args.verdict_packet),
        reentry_block_path=_resolve(root, args.reentry_block),
        lane_a_receipt_path=_resolve(root, args.lane_a_receipt),
        lane_a_scorecard_path=_resolve(root, args.lane_a_scorecard),
        lane_b_receipt_path=_resolve(root, args.lane_b_receipt),
        lane_b_scorecard_path=_resolve(root, args.lane_b_scorecard),
        cross_lane_packet_path=_resolve(root, args.cross_lane_packet),
        dual_lane_a_scorecard_path=_resolve(root, args.dual_lane_a_scorecard),
        dual_lane_b_scorecard_path=_resolve(root, args.dual_lane_b_scorecard),
        third_row_panel_path=_resolve(root, args.third_row_panel),
        route_bearing_manifest_path=_resolve(root, args.route_bearing_manifest),
        route_bearing_index_path=_resolve(root, args.route_bearing_index),
        oracle_local_eval_packet_path=_resolve(root, args.oracle_local_eval_packet),
        single_axis_manifest_path=_resolve(root, args.single_axis_manifest),
        targeted_hypertraining_manifest_path=_resolve(root, args.targeted_hypertraining_manifest),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in (
        "status",
        "execution_status",
        "successor_reentry_prep_packet_authorized",
        "reserve_challenges_pass",
        "output_count",
        "receipt_path",
        "subject_head",
    ):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
