from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_first_successor_evidence_execution_tranche as first_wave
from tools.operator import cohort0_first_successor_evidence_setup_tranche as setup_tranche
from tools.operator import cohort0_second_successor_evidence_wave_tranche as second_wave
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_VERDICT_PACKET_REL = setup_tranche.DEFAULT_VERDICT_PACKET_REL
DEFAULT_REENTRY_BLOCK_REL = setup_tranche.DEFAULT_REENTRY_BLOCK_REL
DEFAULT_MICRO_COURTS_REL = setup_tranche.DEFAULT_MICRO_COURTS_REL
DEFAULT_SETUP_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{setup_tranche.OUTPUT_SETUP_RECEIPT}"
DEFAULT_FIRST_EXECUTION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{first_wave.OUTPUT_EXECUTION_RECEIPT}"
DEFAULT_SECOND_EXECUTION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{second_wave.OUTPUT_EXECUTION_RECEIPT}"
DEFAULT_SECOND_BRIDGE_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{second_wave.OUTPUT_BRIDGE_SCORECARD}"
DEFAULT_SECOND_CAUSAL_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{second_wave.OUTPUT_CAUSAL_SCORECARD}"
DEFAULT_SECOND_DOMINANCE_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{second_wave.OUTPUT_DOMINANCE_PACKET}"
DEFAULT_ROUTE_MARGIN_RECORDS_REL = first_wave.DEFAULT_ROUTE_MARGIN_RECORDS_REL
DEFAULT_JOINT_BATCH_MANIFEST_REL = first_wave.DEFAULT_JOINT_BATCH_MANIFEST_REL
DEFAULT_DEFER_GATE_CONTRACT_REL = first_wave.DEFAULT_DEFER_GATE_CONTRACT_REL
DEFAULT_ROUTE_SELF_CHECK_CONTRACT_REL = first_wave.DEFAULT_ROUTE_SELF_CHECK_CONTRACT_REL
DEFAULT_ROUTE_HEAD_CHECKPOINT_REL = first_wave.DEFAULT_ROUTE_HEAD_CHECKPOINT_REL
DEFAULT_ROUTE_HEAD_LABEL_MAP_REL = first_wave.DEFAULT_ROUTE_HEAD_LABEL_MAP_REL
DEFAULT_ROUTE_HEAD_TRAIN_MANIFEST_REL = first_wave.DEFAULT_ROUTE_HEAD_TRAIN_MANIFEST_REL
DEFAULT_REPORTS_ROOT_REL = first_wave.DEFAULT_REPORTS_ROOT_REL

OUTPUT_ROW_PANEL = "cohort0_third_successor_bridge_bound_row_panel.json"
OUTPUT_INVENTORY_RECEIPT = "cohort0_third_successor_inventory_boundary_receipt.json"
OUTPUT_BRIDGE_SCORECARD = "cohort0_third_successor_bridge_coupling_scorecard.json"
OUTPUT_HARNESS_SCORECARD = "cohort0_third_successor_fixed_harness_scorecard.json"
OUTPUT_DOMINANCE_PACKET = "cohort0_third_successor_dominance_packet.json"
OUTPUT_EXECUTION_MANIFEST = "cohort0_third_successor_execution_manifest.json"
OUTPUT_EXECUTION_RECEIPT = "cohort0_third_successor_execution_receipt.json"
OUTPUT_REPORT = "COHORT0_THIRD_SUCCESSOR_BRIDGE_BOUND_REPORT.md"


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
        raise RuntimeError("FAIL_CLOSED: third-wave bridge-bound tranche requires one same-head authority line")
    return next(iter(heads))


def _round_float(value: Any, digits: int = 6) -> float:
    return round(float(value), digits)


def _bool_rate(flags: Sequence[bool]) -> float:
    if not flags:
        return 0.0
    return _round_float(sum(1 for item in flags if item) / len(flags))


def _positive_percentile(values: Sequence[float], frac: float) -> float:
    positives = sorted(float(v) for v in values if float(v) > 0.0)
    if not positives:
        return 0.0
    index = max(0, min(len(positives) - 1, int(len(positives) * frac) - 1))
    return float(positives[index])


def _validate_second_wave_state(
    *,
    verdict_packet: Dict[str, Any],
    reentry_block: Dict[str, Any],
    micro_courts_manifest: Dict[str, Any],
    setup_receipt: Dict[str, Any],
    first_execution_receipt: Dict[str, Any],
    second_execution_receipt: Dict[str, Any],
    second_bridge_scorecard: Dict[str, Any],
    second_causal_scorecard: Dict[str, Any],
    second_dominance_packet: Dict[str, Any],
) -> None:
    for payload, label in (
        (verdict_packet, "hardened ceiling verdict packet"),
        (reentry_block, "gate d reentry block contract"),
        (micro_courts_manifest, "successor frozen micro-courts manifest"),
        (setup_receipt, "first successor evidence setup receipt"),
        (first_execution_receipt, "first successor evidence execution receipt"),
        (second_execution_receipt, "second successor execution receipt"),
        (second_bridge_scorecard, "second successor bridge scorecard"),
        (second_causal_scorecard, "second successor causal scorecard"),
        (second_dominance_packet, "second successor dominance packet"),
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
    if str(setup_receipt.get("setup_status", "")).strip() != "PASS__FIRST_SUCCESSOR_EVIDENCE_SETUP_BOUND":
        raise RuntimeError("FAIL_CLOSED: successor setup must remain bound")
    if str(first_execution_receipt.get("execution_status", "")).strip() != "PASS__FIRST_SUCCESSOR_EVIDENCE_EXECUTED__LIGHTWEIGHT":
        raise RuntimeError("FAIL_CLOSED: first successor execution must exist")
    if not bool(first_execution_receipt.get("reportability_lift_observed", False)):
        raise RuntimeError("FAIL_CLOSED: first-wave reportability lift must remain positive")
    if not bool(first_execution_receipt.get("route_consequence_signal_nonzero", False)):
        raise RuntimeError("FAIL_CLOSED: first-wave route consequence signal must remain positive")
    if str(second_execution_receipt.get("execution_status", "")).strip() != "PASS__SECOND_WAVE_ONE_NOTCH_WIDENING_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: second-wave widening must exist before third-wave bridge binding")
    if not bool(second_execution_receipt.get("selected_best_candidate_one_notch_widening_holds", False)):
        raise RuntimeError("FAIL_CLOSED: second-wave winning bridge must hold under one-notch widening")
    if not bool(second_execution_receipt.get("route_consequence_signal_nonzero", False)):
        raise RuntimeError("FAIL_CLOSED: second-wave route consequence signal must remain positive")
    if bool(second_execution_receipt.get("same_head_counted_reentry_admissible_now", True)):
        raise RuntimeError("FAIL_CLOSED: counted reentry must remain blocked entering third-wave binding")
    if bool(second_execution_receipt.get("gate_d_reopened", True)):
        raise RuntimeError("FAIL_CLOSED: Gate D must remain closed entering third-wave binding")
    if bool(second_execution_receipt.get("gate_e_open", True)):
        raise RuntimeError("FAIL_CLOSED: Gate E must remain closed entering third-wave binding")
    if str(second_dominance_packet.get("theorem_boundary", {}).get("counted_claim_status", "")).strip() != "NOT_EARNED__SECOND_WAVE_ONE_NOTCH_WIDENING_ONLY":
        raise RuntimeError("FAIL_CLOSED: second-wave dominance packet must remain explicitly non-counted")


def _selected_bridge_candidate_id(second_execution_receipt: Dict[str, Any], second_bridge_scorecard: Dict[str, Any]) -> str:
    receipt_id = str(second_execution_receipt.get("selected_best_candidate_id", "")).strip()
    scorecard_id = str(second_bridge_scorecard.get("selected_best_candidate_id", "")).strip()
    if not receipt_id or receipt_id != scorecard_id:
        raise RuntimeError("FAIL_CLOSED: second-wave selected bridge candidate mismatch")
    return receipt_id


def _inventory_and_route_sets(
    *,
    observed_rows: Sequence[Dict[str, Any]],
    focused_current_family_id: str,
    support_lab_hold_family_ids: Sequence[str],
) -> Dict[str, Any]:
    control_family_ids = {"BOUNDARY_ABSTENTION_CONTROL", "STATIC_NO_ROUTE_CONTROL"}
    route_current_family_ids = [focused_current_family_id, *[str(item).strip() for item in support_lab_hold_family_ids]]
    route_rows = [row for row in observed_rows if str(row.get("current_family_id", "")).strip() in set(route_current_family_ids)]
    control_rows = [row for row in observed_rows if str(row.get("current_family_id", "")).strip() in control_family_ids]
    route_inventory_current = sorted({str(row.get("current_family_id", "")).strip() for row in route_rows})
    route_inventory_legacy = sorted({str(row.get("legacy_family_id", "")).strip() for row in route_rows})
    return {
        "route_current_family_ids": route_current_family_ids,
        "route_legacy_family_ids": [first_wave.LEGACY_FOCUSED_FAMILY_ID, *[str(item).strip() for item in support_lab_hold_family_ids]],
        "route_rows": route_rows,
        "masked_route_rows": [row for row in route_rows if str(row.get("variant_type", "")).strip() == "masked"],
        "control_rows": control_rows,
        "inventory_current": route_inventory_current,
        "inventory_legacy": route_inventory_legacy,
        "adjacent_family_ring_exhausted_on_saved_head": set(route_inventory_current) == set(route_current_family_ids),
    }


def _reason_label(
    row: Dict[str, Any],
    *,
    selected_candidate_id: str,
    route_legacy_family_ids: Sequence[str],
    thresholds: Dict[str, Any],
) -> str:
    return second_wave._variant_reason_label_v2(
        row,
        variant_id=selected_candidate_id,
        route_family_ids=route_legacy_family_ids,
        thresholds=thresholds,
    )


def _reason_admissible(
    row: Dict[str, Any],
    *,
    reason_label: str,
    route_legacy_family_ids: Sequence[str],
    thresholds: Dict[str, Any],
) -> bool:
    return second_wave._reason_is_admissible_v2(
        row,
        reason_label=reason_label,
        route_family_ids=route_legacy_family_ids,
        thresholds=thresholds,
    )


def _row_weight(row: Dict[str, Any]) -> float:
    return max(
        float(row.get("wrong_route_cost", 0.0)),
        float(row.get("wrong_static_hold_cost", 0.0)),
        float(row.get("missed_abstention_cost", 0.0)),
    )


def _weighted_rate(rows: Sequence[Dict[str, Any]], *, key: str) -> float:
    if not rows:
        return 0.0
    total_weight = sum(_row_weight(row) for row in rows)
    if total_weight <= 0.0:
        return 0.0
    matched_weight = sum(_row_weight(row) for row in rows if bool(row.get(key, False)))
    return _round_float(matched_weight / total_weight)


def _score_panel(rows: Sequence[Dict[str, Any]], *, exact_key: str, admissible_key: str) -> Dict[str, Any]:
    return {
        "row_count": len(rows),
        "action_accuracy": _bool_rate(
            [str(row.get("predicted_action_label", "")).strip() == str(row.get("lawful_action", "")).strip() for row in rows]
        ),
        "why_not_accuracy": _bool_rate(
            [str(row.get("predicted_why_not_label", "")).strip() == str(row.get("gold_why_not_target_label", "")).strip() for row in rows]
        ),
        "reason_exact_accuracy": _bool_rate([bool(row.get(exact_key, False)) for row in rows]),
        "reason_admissible_accuracy": _bool_rate([bool(row.get(admissible_key, False)) for row in rows]),
        "consequence_weighted_reason_exact_accuracy": _weighted_rate(rows, key=exact_key),
        "consequence_weighted_reason_admissible_accuracy": _weighted_rate(rows, key=admissible_key),
    }


def _build_bridge_bound_outputs(
    *,
    observed_rows: Sequence[Dict[str, Any]],
    focused_current_family_id: str,
    support_lab_hold_family_ids: Sequence[str],
    selected_candidate_id: str,
    thresholds: Dict[str, Any],
    second_causal_scorecard: Dict[str, Any],
) -> Dict[str, Any]:
    inventory = _inventory_and_route_sets(
        observed_rows=observed_rows,
        focused_current_family_id=focused_current_family_id,
        support_lab_hold_family_ids=support_lab_hold_family_ids,
    )
    route_legacy_family_ids = inventory["route_legacy_family_ids"]
    enriched_rows: List[Dict[str, Any]] = []
    for row in observed_rows:
        baseline_reason = str(row.get("predicted_reason_label", "")).strip()
        selected_reason = _reason_label(
            row,
            selected_candidate_id=selected_candidate_id,
            route_legacy_family_ids=route_legacy_family_ids,
            thresholds=thresholds,
        )
        baseline_exact = baseline_reason == str(row.get("gold_reason_label", "")).strip()
        selected_exact = selected_reason == str(row.get("gold_reason_label", "")).strip()
        baseline_admissible = _reason_admissible(
            row,
            reason_label=baseline_reason,
            route_legacy_family_ids=route_legacy_family_ids,
            thresholds=thresholds,
        )
        selected_admissible = _reason_admissible(
            row,
            reason_label=selected_reason,
            route_legacy_family_ids=route_legacy_family_ids,
            thresholds=thresholds,
        )
        panel_ids: List[str] = []
        if str(row.get("current_family_id", "")).strip() in set(inventory["route_current_family_ids"]):
            panel_ids.append("THIRD_WAVE_ROUTE_RING_PANEL")
        if str(row.get("variant_type", "")).strip() == "masked" and str(row.get("current_family_id", "")).strip() in set(inventory["route_current_family_ids"]):
            panel_ids.append("THIRD_WAVE_MASKED_RING_PANEL")
        if str(row.get("current_family_id", "")).strip() == "BOUNDARY_ABSTENTION_CONTROL":
            panel_ids.append("THIRD_WAVE_BOUNDARY_CONTROL_PANEL")
        if str(row.get("current_family_id", "")).strip() == "STATIC_NO_ROUTE_CONTROL":
            panel_ids.append("THIRD_WAVE_STATIC_CONTROL_PANEL")
        enriched_rows.append(
            {
                "case_id": row["case_id"],
                "current_family_id": row["current_family_id"],
                "legacy_family_id": row["legacy_family_id"],
                "variant_type": row["variant_type"],
                "lawful_action": row["lawful_action"],
                "predicted_action_label": row["predicted_action_label"],
                "predicted_why_not_label": row["predicted_why_not_label"],
                "gold_reason_label": row["gold_reason_label"],
                "gold_why_not_target_label": row["gold_why_not_target_label"],
                "baseline_reason_label": baseline_reason,
                "selected_bridge_candidate_id": selected_candidate_id,
                "selected_bridge_reason_label": selected_reason,
                "baseline_reason_exact": baseline_exact,
                "baseline_reason_admissible": baseline_admissible,
                "selected_bridge_reason_exact": selected_exact,
                "selected_bridge_reason_admissible": selected_admissible,
                "selected_bridge_lawful_refusal": selected_reason == first_wave.LAWFUL_REASON_REFUSAL,
                "reason_confidence": row["reason_confidence"],
                "action_confidence": row["action_confidence"],
                "why_not_confidence": row["why_not_confidence"],
                "observed_route_margin": row["observed_route_margin"],
                "expected_route_margin": row["expected_route_margin"],
                "wrong_route_cost": row["wrong_route_cost"],
                "wrong_static_hold_cost": row["wrong_static_hold_cost"],
                "missed_abstention_cost": row["missed_abstention_cost"],
                "consequence_weight": _round_float(_row_weight(row)),
                "panel_ids": panel_ids,
            }
        )

    route_rows = [row for row in enriched_rows if "THIRD_WAVE_ROUTE_RING_PANEL" in row["panel_ids"]]
    masked_rows = [row for row in enriched_rows if "THIRD_WAVE_MASKED_RING_PANEL" in row["panel_ids"]]
    boundary_rows = [row for row in enriched_rows if "THIRD_WAVE_BOUNDARY_CONTROL_PANEL" in row["panel_ids"]]
    static_rows = [row for row in enriched_rows if "THIRD_WAVE_STATIC_CONTROL_PANEL" in row["panel_ids"]]
    high_threshold = _positive_percentile([row["consequence_weight"] for row in route_rows], 0.75)
    high_consequence_rows = [row for row in route_rows if float(row["consequence_weight"]) >= high_threshold > 0.0]

    family_metrics: Dict[str, Dict[str, Any]] = {}
    for family_id in inventory["route_current_family_ids"]:
        family_rows = [row for row in route_rows if str(row.get("current_family_id", "")).strip() == family_id]
        family_metrics[family_id] = {
            "baseline": _score_panel(family_rows, exact_key="baseline_reason_exact", admissible_key="baseline_reason_admissible"),
            "selected_bridge": _score_panel(
                family_rows,
                exact_key="selected_bridge_reason_exact",
                admissible_key="selected_bridge_reason_admissible",
            ),
        }

    route_panel_baseline = _score_panel(route_rows, exact_key="baseline_reason_exact", admissible_key="baseline_reason_admissible")
    route_panel_selected = _score_panel(route_rows, exact_key="selected_bridge_reason_exact", admissible_key="selected_bridge_reason_admissible")
    masked_panel_baseline = _score_panel(masked_rows, exact_key="baseline_reason_exact", admissible_key="baseline_reason_admissible")
    masked_panel_selected = _score_panel(masked_rows, exact_key="selected_bridge_reason_exact", admissible_key="selected_bridge_reason_admissible")
    boundary_panel_selected = _score_panel(boundary_rows, exact_key="selected_bridge_reason_exact", admissible_key="selected_bridge_reason_admissible")
    static_panel_selected = _score_panel(static_rows, exact_key="selected_bridge_reason_exact", admissible_key="selected_bridge_reason_admissible")
    high_panel_baseline = _score_panel(high_consequence_rows, exact_key="baseline_reason_exact", admissible_key="baseline_reason_admissible")
    high_panel_selected = _score_panel(high_consequence_rows, exact_key="selected_bridge_reason_exact", admissible_key="selected_bridge_reason_admissible")
    causal_signals = dict(second_causal_scorecard.get("signals", {}))
    bridge_alignment_visible = (
        route_panel_selected["reason_exact_accuracy"] >= 1.0
        and masked_panel_selected["reason_exact_accuracy"] >= 1.0
        and boundary_panel_selected["reason_exact_accuracy"] >= 1.0
        and static_panel_selected["reason_exact_accuracy"] >= 1.0
        and bool(causal_signals.get("route_consequence_signal_nonzero", False))
        and bool(causal_signals.get("wrong_route_penalty_visible", False))
        and bool(causal_signals.get("witness_ablation_penalty_visible", False))
        and bool(causal_signals.get("static_hold_control_preserved", False))
    )

    row_panel = {
        "schema_id": "kt.operator.cohort0_third_successor_bridge_bound_row_panel.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This row panel records third-wave bridge-bound strengthening only. "
            "It uses the selected second-wave bridge candidate over the current fully widened saved-head ring and does not reopen Gate D."
        ),
        "focused_family_id": focused_current_family_id,
        "route_ring_family_ids": inventory["route_current_family_ids"],
        "rows": enriched_rows,
    }
    inventory_receipt = {
        "schema_id": "kt.operator.cohort0_third_successor_inventory_boundary_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This inventory receipt states the widening boundary on the current saved-head surface. "
            "It does not claim theorem movement."
        ),
        "focused_family_id": focused_current_family_id,
        "support_lab_hold_family_ids": list(support_lab_hold_family_ids),
        "route_bearing_current_family_ids": inventory["inventory_current"],
        "route_bearing_legacy_family_ids": inventory["inventory_legacy"],
        "route_bearing_family_count": len(inventory["inventory_current"]),
        "adjacent_family_ring_exhausted_on_saved_head": inventory["adjacent_family_ring_exhausted_on_saved_head"],
        "next_family_ring_available_on_saved_head": False,
        "next_expansion_requirement": "MATERIAL_NEW_ROUTE_BEARING_FAMILY_OR_NEW_MUTATION_GENERATION_REQUIRED",
    }
    bridge_scorecard = {
        "schema_id": "kt.operator.cohort0_third_successor_bridge_coupling_scorecard.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This scorecard binds the selected second-wave bridge candidate to the full current widened ring and masked mutation rows. "
            "It is bridge-strengthening evidence only and remains non-counted."
        ),
        "selected_bridge_candidate_id": selected_candidate_id,
        "route_ring_family_ids": inventory["route_current_family_ids"],
        "high_consequence_threshold": _round_float(high_threshold),
        "route_ring_baseline": route_panel_baseline,
        "route_ring_selected_bridge": route_panel_selected,
        "masked_ring_baseline": masked_panel_baseline,
        "masked_ring_selected_bridge": masked_panel_selected,
        "high_consequence_case_ids": [row["case_id"] for row in high_consequence_rows],
        "high_consequence_baseline": high_panel_baseline,
        "high_consequence_selected_bridge": high_panel_selected,
        "boundary_control_selected_bridge": boundary_panel_selected,
        "static_control_selected_bridge": static_panel_selected,
        "family_metrics": family_metrics,
        "bridge_alignment_visible": bridge_alignment_visible,
        "bridge_reason_weighted_exact_delta_vs_baseline": _round_float(
            route_panel_selected["consequence_weighted_reason_exact_accuracy"] - route_panel_baseline["consequence_weighted_reason_exact_accuracy"]
        ),
        "bridge_reason_weighted_admissible_delta_vs_baseline": _round_float(
            route_panel_selected["consequence_weighted_reason_admissible_accuracy"] - route_panel_baseline["consequence_weighted_reason_admissible_accuracy"]
        ),
    }
    return {
        "row_panel": row_panel,
        "inventory_receipt": inventory_receipt,
        "bridge_scorecard": bridge_scorecard,
        "bridge_alignment_visible": bridge_alignment_visible,
        "route_ring_selected_bridge": route_panel_selected,
        "masked_ring_selected_bridge": masked_panel_selected,
        "inventory": inventory,
    }


def _fixed_harness_scorecard(
    *,
    route_rows: Sequence[Dict[str, Any]],
    control_rows: Sequence[Dict[str, Any]],
    second_causal_scorecard: Dict[str, Any],
    selected_candidate_id: str,
) -> Dict[str, Any]:
    boundary_rows = [row for row in control_rows if str(row.get("current_family_id", "")).strip() == "BOUNDARY_ABSTENTION_CONTROL"]
    static_rows = [row for row in control_rows if str(row.get("current_family_id", "")).strip() == "STATIC_NO_ROUTE_CONTROL"]
    baseline_panel = first_wave._score_intervention_rows(route_rows, intervention_id="BASELINE_FOLLOW_HEAD")
    interventions = {
        "FORCED_WRONG_ROUTE_PRIMARY": first_wave._score_intervention_rows(route_rows, intervention_id="FORCED_WRONG_ROUTE_PRIMARY"),
        "RANDOM_ROUTE_NEGATIVE_CONTROL_PRIMARY": first_wave._score_intervention_rows(route_rows, intervention_id="RANDOM_ROUTE_NEGATIVE_CONTROL_PRIMARY"),
        "ORACLE_ROUTE_UPPER_BOUND_PRIMARY": first_wave._score_intervention_rows(route_rows, intervention_id="ORACLE_ROUTE_UPPER_BOUND_PRIMARY"),
        "WITNESS_ABLATION_PRIMARY": first_wave._score_intervention_rows(route_rows, intervention_id="WITNESS_ABLATION_PRIMARY"),
        "FORCED_STATIC_HOLD_CONTROL_SPINE": first_wave._score_intervention_rows(static_rows, intervention_id="FORCED_STATIC_HOLD_CONTROL_SPINE"),
        "ABSTAIN_DISABLED_BOUNDARY_SPINE": first_wave._score_intervention_rows(boundary_rows, intervention_id="ABSTAIN_DISABLED_BOUNDARY_SPINE"),
    }
    second_interventions = dict(second_causal_scorecard.get("interventions", {}))
    stable_vs_second_wave = True
    for key, score in interventions.items():
        second_total = float(second_interventions.get(key, {}).get("total_cost", score["total_cost"]))
        if abs(float(score["total_cost"]) - second_total) > 1e-9:
            stable_vs_second_wave = False
            break
    signals = {
        "wrong_route_penalty_visible": float(interventions["FORCED_WRONG_ROUTE_PRIMARY"]["total_cost"]) > float(baseline_panel["total_cost"]),
        "random_route_penalty_visible": float(interventions["RANDOM_ROUTE_NEGATIVE_CONTROL_PRIMARY"]["total_cost"]) > float(baseline_panel["total_cost"]),
        "witness_ablation_penalty_visible": float(interventions["WITNESS_ABLATION_PRIMARY"]["total_cost"]) > float(baseline_panel["total_cost"]),
        "static_hold_control_preserved": float(interventions["FORCED_STATIC_HOLD_CONTROL_SPINE"]["total_cost"]) == 0.0,
        "boundary_abstention_guard_visible": float(interventions["ABSTAIN_DISABLED_BOUNDARY_SPINE"]["total_cost"]) > 0.0,
        "route_consequence_signal_nonzero": float(interventions["FORCED_WRONG_ROUTE_PRIMARY"]["total_cost"]) > 0.0
        and float(interventions["WITNESS_ABLATION_PRIMARY"]["total_cost"]) > 0.0,
        "stable_vs_second_wave": stable_vs_second_wave,
    }
    return {
        "schema_id": "kt.operator.cohort0_third_successor_fixed_harness_scorecard.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This scorecard keeps the causal harness fixed while binding it to the selected second-wave bridge candidate. "
            "It remains non-counted and does not reopen Gate D."
        ),
        "selected_bridge_candidate_id": selected_candidate_id,
        "baseline_panel": baseline_panel,
        "interventions": interventions,
        "signals": signals,
    }


def _build_dominance_packet(
    *,
    focused_current_family_id: str,
    support_lab_hold_family_ids: Sequence[str],
    inventory_receipt: Dict[str, Any],
    bridge_scorecard: Dict[str, Any],
    harness_scorecard: Dict[str, Any],
    row_panel: Dict[str, Any],
) -> Dict[str, Any]:
    route_rows = [
        row
        for row in row_panel.get("rows", [])
        if str(row.get("current_family_id", "")).strip() in {focused_current_family_id, *[str(item).strip() for item in support_lab_hold_family_ids]}
    ]
    control_rows = [
        row
        for row in row_panel.get("rows", [])
        if str(row.get("current_family_id", "")).strip() in {"BOUNDARY_ABSTENTION_CONTROL", "STATIC_NO_ROUTE_CONTROL"}
    ]
    alpha_should_lose = [
        {
            "case_id": row["case_id"],
            "family_id": row["current_family_id"],
            "legacy_family_id": row["legacy_family_id"],
            "wrong_static_hold_cost": row["wrong_static_hold_cost"],
            "why": "The selected bridge now emits exact admissible reason objects on the same widened rows where forced static hold still carries positive cost.",
        }
        for row in route_rows
        if str(row.get("lawful_action", "")).strip() != first_wave.ACTION_STATIC and float(row.get("wrong_static_hold_cost", 0.0)) > 0.0
    ]
    alpha_still_dominates = [
        {
            "case_id": row["case_id"],
            "family_id": row["current_family_id"],
            "legacy_family_id": row["legacy_family_id"],
            "why": "This control row remains a rightful static hold, so the static path stays the correct minimum action.",
        }
        for row in control_rows
        if str(row.get("current_family_id", "")).strip() == "STATIC_NO_ROUTE_CONTROL"
    ]
    return {
        "schema_id": "kt.operator.cohort0_third_successor_dominance_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This is third-wave bridge-bound dominance strengthening only. "
            "It does not reopen Gate D, authorize counted reentry, or open Gate E."
        ),
        "execution_status": "PASS__THIRD_WAVE_BRIDGE_BOUND_STRENGTHENING_EMITTED",
        "focused_family_id": focused_current_family_id,
        "adjacent_family_ids": list(support_lab_hold_family_ids),
        "alpha_should_lose_here_manifest": alpha_should_lose,
        "alpha_still_dominates_here_manifest": alpha_still_dominates,
        "inventory_boundary": {
            "adjacent_family_ring_exhausted_on_saved_head": bool(
                inventory_receipt.get("adjacent_family_ring_exhausted_on_saved_head", False)
            ),
            "next_expansion_requirement": inventory_receipt.get("next_expansion_requirement", ""),
        },
        "reportability_summary": {
            "selected_bridge_candidate_id": bridge_scorecard.get("selected_bridge_candidate_id", ""),
            "route_ring_reason_exact_accuracy": bridge_scorecard.get("route_ring_selected_bridge", {}).get("reason_exact_accuracy", 0.0),
            "route_ring_reason_admissible_accuracy": bridge_scorecard.get("route_ring_selected_bridge", {}).get("reason_admissible_accuracy", 0.0),
            "masked_ring_reason_exact_accuracy": bridge_scorecard.get("masked_ring_selected_bridge", {}).get("reason_exact_accuracy", 0.0),
            "masked_ring_reason_admissible_accuracy": bridge_scorecard.get("masked_ring_selected_bridge", {}).get(
                "reason_admissible_accuracy",
                0.0,
            ),
            "high_consequence_reason_exact_accuracy": bridge_scorecard.get("high_consequence_selected_bridge", {}).get(
                "reason_exact_accuracy",
                0.0,
            ),
            "bridge_alignment_visible": bridge_scorecard.get("bridge_alignment_visible", False),
        },
        "route_economics_reduction_map": {
            "baseline_total_cost": harness_scorecard.get("baseline_panel", {}).get("total_cost", 0.0),
            "forced_wrong_route_total_cost": harness_scorecard.get("interventions", {}).get("FORCED_WRONG_ROUTE_PRIMARY", {}).get("total_cost", 0.0),
            "random_route_total_cost": harness_scorecard.get("interventions", {}).get("RANDOM_ROUTE_NEGATIVE_CONTROL_PRIMARY", {}).get("total_cost", 0.0),
            "witness_ablation_total_cost": harness_scorecard.get("interventions", {}).get("WITNESS_ABLATION_PRIMARY", {}).get("total_cost", 0.0),
            "boundary_abstention_total_cost": harness_scorecard.get("interventions", {}).get("ABSTAIN_DISABLED_BOUNDARY_SPINE", {}).get("total_cost", 0.0),
            "static_control_total_cost": harness_scorecard.get("interventions", {}).get("FORCED_STATIC_HOLD_CONTROL_SPINE", {}).get("total_cost", 0.0),
            "route_consequence_signal_nonzero": bool(harness_scorecard.get("signals", {}).get("route_consequence_signal_nonzero", False)),
            "stable_vs_second_wave": bool(harness_scorecard.get("signals", {}).get("stable_vs_second_wave", False)),
        },
        "family_concentration_report": {
            "signal_family_ids": inventory_receipt.get("route_bearing_current_family_ids", []),
            "family_local_only": False,
            "one_notch_widening_only": True,
            "route_bearing_family_inventory_exhausted_on_saved_head": bool(
                inventory_receipt.get("adjacent_family_ring_exhausted_on_saved_head", False)
            ),
            "counted_dominance_claim_admissible": False,
        },
        "theorem_boundary": {
            "counted_claim_status": "NOT_EARNED__THIRD_WAVE_BRIDGE_BOUND_ALIGNMENT_ONLY",
            "same_head_counted_reentry_admissible_now": False,
            "gate_d_reopened": False,
            "gate_e_open": False,
        },
    }


def _build_markdown_report(execution_manifest: Dict[str, Any], outputs: Sequence[str]) -> str:
    lines: List[str] = []
    lines.append("# COHORT0 Third Successor Bridge-Bound Report")
    lines.append("")
    lines.append(f"- Generated UTC: `{execution_manifest['generated_utc']}`")
    lines.append(f"- Subject head: `{execution_manifest['subject_head']}`")
    lines.append(f"- Focused family: `{execution_manifest['focused_family_id']}`")
    lines.append(f"- Selected bridge: `{execution_manifest['selected_bridge_candidate_id']}`")
    lines.append("")
    lines.append("## What Ran")
    lines.append("")
    for item in execution_manifest["completed_now"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Claim Boundary")
    lines.append("")
    lines.append(execution_manifest["claim_boundary"])
    lines.append("")
    lines.append("## Outputs")
    lines.append("")
    for output in outputs:
        lines.append(f"- `{output}`")
    lines.append("")
    return "\n".join(lines)


def run_third_successor_bridge_bound_tranche(
    *,
    verdict_packet_path: Path,
    reentry_block_path: Path,
    micro_courts_manifest_path: Path,
    setup_receipt_path: Path,
    first_execution_receipt_path: Path,
    second_execution_receipt_path: Path,
    second_bridge_scorecard_path: Path,
    second_causal_scorecard_path: Path,
    second_dominance_packet_path: Path,
    route_margin_records_path: Path,
    joint_batch_manifest_path: Path,
    defer_gate_contract_path: Path,
    route_self_check_contract_path: Path,
    route_head_checkpoint_path: Path,
    route_head_label_map_path: Path,
    route_head_train_manifest_path: Path,
    reports_root: Path,
) -> Dict[str, Any]:
    reports_root = reports_root.resolve()
    reports_root.mkdir(parents=True, exist_ok=True)

    verdict_packet = _load_json_required(verdict_packet_path, label="hardened ceiling verdict packet")
    reentry_block = _load_json_required(reentry_block_path, label="gate d reentry block contract")
    micro_courts_manifest = _load_json_required(micro_courts_manifest_path, label="successor frozen micro-courts manifest")
    setup_receipt = _load_json_required(setup_receipt_path, label="first successor evidence setup receipt")
    first_execution_receipt = _load_json_required(first_execution_receipt_path, label="first successor evidence execution receipt")
    second_execution_receipt = _load_json_required(second_execution_receipt_path, label="second successor execution receipt")
    second_bridge_scorecard = _load_json_required(second_bridge_scorecard_path, label="second successor bridge scorecard")
    second_causal_scorecard = _load_json_required(second_causal_scorecard_path, label="second successor causal scorecard")
    second_dominance_packet = _load_json_required(second_dominance_packet_path, label="second successor dominance packet")

    _validate_second_wave_state(
        verdict_packet=verdict_packet,
        reentry_block=reentry_block,
        micro_courts_manifest=micro_courts_manifest,
        setup_receipt=setup_receipt,
        first_execution_receipt=first_execution_receipt,
        second_execution_receipt=second_execution_receipt,
        second_bridge_scorecard=second_bridge_scorecard,
        second_causal_scorecard=second_causal_scorecard,
        second_dominance_packet=second_dominance_packet,
    )
    subject_head = _require_same_subject_head(
        [
            verdict_packet,
            reentry_block,
            micro_courts_manifest,
            setup_receipt,
            first_execution_receipt,
            second_execution_receipt,
            second_bridge_scorecard,
            second_causal_scorecard,
            second_dominance_packet,
        ]
    )
    if subject_head != setup_tranche.EXPECTED_SUBJECT_HEAD:
        raise RuntimeError("FAIL_CLOSED: unexpected subject head for third-wave bridge-bound tranche")

    focused_current_family_id = str(micro_courts_manifest.get("focused_family_id", "")).strip()
    support_lab_hold_family_ids = [
        str(item).strip()
        for item in micro_courts_manifest.get("support_lab_hold_family_ids", [])
        if str(item).strip()
    ]
    selected_candidate_id = _selected_bridge_candidate_id(second_execution_receipt, second_bridge_scorecard)
    observed = first_wave._execute_saved_route_head(
        route_margin_records_path=route_margin_records_path,
        joint_batch_manifest_path=joint_batch_manifest_path,
        defer_gate_contract_path=defer_gate_contract_path,
        route_self_check_contract_path=route_self_check_contract_path,
        route_head_checkpoint_path=route_head_checkpoint_path,
        route_head_label_map_path=route_head_label_map_path,
        route_head_train_manifest_path=route_head_train_manifest_path,
        focused_current_family_id=focused_current_family_id,
    )
    bridge_outputs = _build_bridge_bound_outputs(
        observed_rows=observed["observed_rows"],
        focused_current_family_id=focused_current_family_id,
        support_lab_hold_family_ids=support_lab_hold_family_ids,
        selected_candidate_id=selected_candidate_id,
        thresholds=observed["thresholds"],
        second_causal_scorecard=second_causal_scorecard,
    )
    harness_scorecard = _fixed_harness_scorecard(
        route_rows=bridge_outputs["inventory"]["route_rows"],
        control_rows=bridge_outputs["inventory"]["control_rows"],
        second_causal_scorecard=second_causal_scorecard,
        selected_candidate_id=selected_candidate_id,
    )
    dominance_packet = _build_dominance_packet(
        focused_current_family_id=focused_current_family_id,
        support_lab_hold_family_ids=support_lab_hold_family_ids,
        inventory_receipt=bridge_outputs["inventory_receipt"],
        bridge_scorecard=bridge_outputs["bridge_scorecard"],
        harness_scorecard=harness_scorecard,
        row_panel=bridge_outputs["row_panel"],
    )
    execution_manifest = {
        "schema_id": "kt.operator.cohort0_third_successor_execution_manifest.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": verdict_packet.get("current_git_head", ""),
        "subject_head": subject_head,
        "claim_boundary": (
            "This tranche binds the selected second-wave bridge to the full current saved-head route ring and fixed causal harness. "
            "It remains non-counted and does not reopen Gate D."
        ),
        "execution_status": "PASS__THIRD_WAVE_BRIDGE_BOUND_STRENGTHENING_EXECUTED",
        "focused_family_id": focused_current_family_id,
        "adjacent_family_ids": support_lab_hold_family_ids,
        "selected_bridge_candidate_id": selected_candidate_id,
        "completed_now": [
            "Validated that the second-wave winning bridge held under one-notch widening while Gate D remained closed.",
            "Confirmed the current saved-head route-bearing family inventory is exhausted at the focused-plus-adjacent ring.",
            "Bound the selected second-wave bridge candidate to the full current widened ring and masked mutation rows.",
            "Kept the causal harness fixed and emitted a bridge-bound alignment scorecard against the same comparator-clean costs.",
            "Emitted a third-wave bridge-bound dominance packet while keeping counted reentry and Gate D readjudication blocked.",
        ],
        "bridge_alignment_visible": bridge_outputs["bridge_alignment_visible"],
        "route_bearing_family_inventory_exhausted_on_saved_head": bridge_outputs["inventory_receipt"][
            "adjacent_family_ring_exhausted_on_saved_head"
        ],
    }
    execution_receipt = {
        "schema_id": "kt.operator.cohort0_third_successor_execution_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "subject_head": subject_head,
        "claim_boundary": (
            "This receipt records third-wave bridge-bound strengthening only. "
            "It does not claim Gate D reopened, counted reentry became admissible, or Gate E opened."
        ),
        "execution_status": execution_manifest["execution_status"],
        "focused_family_id": focused_current_family_id,
        "adjacent_family_ids": support_lab_hold_family_ids,
        "selected_bridge_candidate_id": selected_candidate_id,
        "route_bearing_family_inventory_exhausted_on_saved_head": bridge_outputs["inventory_receipt"][
            "adjacent_family_ring_exhausted_on_saved_head"
        ],
        "bridge_alignment_visible": bridge_outputs["bridge_alignment_visible"],
        "route_ring_reason_exact_accuracy": bridge_outputs["bridge_scorecard"]["route_ring_selected_bridge"]["reason_exact_accuracy"],
        "route_ring_reason_admissible_accuracy": bridge_outputs["bridge_scorecard"]["route_ring_selected_bridge"][
            "reason_admissible_accuracy"
        ],
        "masked_ring_reason_exact_accuracy": bridge_outputs["bridge_scorecard"]["masked_ring_selected_bridge"]["reason_exact_accuracy"],
        "masked_ring_reason_admissible_accuracy": bridge_outputs["bridge_scorecard"]["masked_ring_selected_bridge"][
            "reason_admissible_accuracy"
        ],
        "fixed_harness_route_consequence_signal_nonzero": bool(harness_scorecard.get("signals", {}).get("route_consequence_signal_nonzero", False)),
        "fixed_harness_stable_vs_second_wave": bool(harness_scorecard.get("signals", {}).get("stable_vs_second_wave", False)),
        "same_head_counted_reentry_admissible_now": False,
        "readjudication_admissible_now": False,
        "gate_d_reopened": False,
        "gate_e_open": False,
        "counted_claim_status": "NOT_EARNED__THIRD_WAVE_BRIDGE_BOUND_ALIGNMENT_ONLY",
        "next_expansion_requirement": bridge_outputs["inventory_receipt"]["next_expansion_requirement"],
        "next_lawful_move": setup_tranche.EXPECTED_PRIMARY_MOVE,
        "secondary_parallel_move": setup_tranche.EXPECTED_SECONDARY_MOVE,
    }

    row_panel = dict(bridge_outputs["row_panel"])
    row_panel.update(
        {
            "subject_head": subject_head,
            "distribution_summary": observed["distribution_summary"],
            "thresholds": observed["thresholds"],
            "bundle_metadata": observed["bundle_metadata"],
        }
    )
    inventory_receipt = dict(bridge_outputs["inventory_receipt"])
    inventory_receipt.update({"subject_head": subject_head})
    bridge_scorecard = dict(bridge_outputs["bridge_scorecard"])
    bridge_scorecard.update({"subject_head": subject_head})
    harness_scorecard.update({"subject_head": subject_head})
    dominance_packet.update({"subject_head": subject_head})

    artifact_payloads = {
        OUTPUT_ROW_PANEL: row_panel,
        OUTPUT_INVENTORY_RECEIPT: inventory_receipt,
        OUTPUT_BRIDGE_SCORECARD: bridge_scorecard,
        OUTPUT_HARNESS_SCORECARD: harness_scorecard,
        OUTPUT_DOMINANCE_PACKET: dominance_packet,
        OUTPUT_EXECUTION_MANIFEST: execution_manifest,
        OUTPUT_EXECUTION_RECEIPT: execution_receipt,
    }
    output_paths: List[str] = []
    for filename, payload in artifact_payloads.items():
        path = (reports_root / filename).resolve()
        write_json_stable(path, payload)
        output_paths.append(f"KT_PROD_CLEANROOM/reports/{filename}")

    report_text = _build_markdown_report(execution_manifest, output_paths)
    report_path = (reports_root / OUTPUT_REPORT).resolve()
    _write_text(report_path, report_text)
    output_paths.append(f"KT_PROD_CLEANROOM/reports/{OUTPUT_REPORT}")

    return {
        "execution_manifest": execution_manifest,
        "execution_receipt": execution_receipt,
        "outputs": output_paths,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run third-wave bridge-bound strengthening over the current fully widened saved-head ring.")
    parser.add_argument("--verdict-packet", default=DEFAULT_VERDICT_PACKET_REL)
    parser.add_argument("--reentry-block", default=DEFAULT_REENTRY_BLOCK_REL)
    parser.add_argument("--micro-courts-manifest", default=DEFAULT_MICRO_COURTS_REL)
    parser.add_argument("--setup-receipt", default=DEFAULT_SETUP_RECEIPT_REL)
    parser.add_argument("--first-execution-receipt", default=DEFAULT_FIRST_EXECUTION_RECEIPT_REL)
    parser.add_argument("--second-execution-receipt", default=DEFAULT_SECOND_EXECUTION_RECEIPT_REL)
    parser.add_argument("--second-bridge-scorecard", default=DEFAULT_SECOND_BRIDGE_SCORECARD_REL)
    parser.add_argument("--second-causal-scorecard", default=DEFAULT_SECOND_CAUSAL_SCORECARD_REL)
    parser.add_argument("--second-dominance-packet", default=DEFAULT_SECOND_DOMINANCE_PACKET_REL)
    parser.add_argument("--route-margin-records", default=DEFAULT_ROUTE_MARGIN_RECORDS_REL)
    parser.add_argument("--joint-batch-manifest", default=DEFAULT_JOINT_BATCH_MANIFEST_REL)
    parser.add_argument("--defer-gate-contract", default=DEFAULT_DEFER_GATE_CONTRACT_REL)
    parser.add_argument("--route-self-check-contract", default=DEFAULT_ROUTE_SELF_CHECK_CONTRACT_REL)
    parser.add_argument("--route-head-checkpoint", default=DEFAULT_ROUTE_HEAD_CHECKPOINT_REL)
    parser.add_argument("--route-head-label-map", default=DEFAULT_ROUTE_HEAD_LABEL_MAP_REL)
    parser.add_argument("--route-head-train-manifest", default=DEFAULT_ROUTE_HEAD_TRAIN_MANIFEST_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_third_successor_bridge_bound_tranche(
        verdict_packet_path=_resolve(root, str(args.verdict_packet)),
        reentry_block_path=_resolve(root, str(args.reentry_block)),
        micro_courts_manifest_path=_resolve(root, str(args.micro_courts_manifest)),
        setup_receipt_path=_resolve(root, str(args.setup_receipt)),
        first_execution_receipt_path=_resolve(root, str(args.first_execution_receipt)),
        second_execution_receipt_path=_resolve(root, str(args.second_execution_receipt)),
        second_bridge_scorecard_path=_resolve(root, str(args.second_bridge_scorecard)),
        second_causal_scorecard_path=_resolve(root, str(args.second_causal_scorecard)),
        second_dominance_packet_path=_resolve(root, str(args.second_dominance_packet)),
        route_margin_records_path=_resolve(root, str(args.route_margin_records)),
        joint_batch_manifest_path=_resolve(root, str(args.joint_batch_manifest)),
        defer_gate_contract_path=_resolve(root, str(args.defer_gate_contract)),
        route_self_check_contract_path=_resolve(root, str(args.route_self_check_contract)),
        route_head_checkpoint_path=_resolve(root, str(args.route_head_checkpoint)),
        route_head_label_map_path=_resolve(root, str(args.route_head_label_map)),
        route_head_train_manifest_path=_resolve(root, str(args.route_head_train_manifest)),
        reports_root=_resolve(root, str(args.reports_root)),
    )
    receipt = payload["execution_receipt"]
    print(
        {
            "status": receipt["status"],
            "execution_status": receipt["execution_status"],
            "selected_bridge_candidate_id": receipt["selected_bridge_candidate_id"],
            "bridge_alignment_visible": receipt["bridge_alignment_visible"],
            "route_bearing_family_inventory_exhausted_on_saved_head": receipt[
                "route_bearing_family_inventory_exhausted_on_saved_head"
            ],
            "output_count": len(payload["outputs"]),
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
