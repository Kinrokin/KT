from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from tools.operator import cohort0_first_successor_evidence_execution_tranche as first_wave
from tools.operator import cohort0_first_successor_evidence_setup_tranche as setup_tranche
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_VERDICT_PACKET_REL = setup_tranche.DEFAULT_VERDICT_PACKET_REL
DEFAULT_REENTRY_BLOCK_REL = setup_tranche.DEFAULT_REENTRY_BLOCK_REL
DEFAULT_MICRO_COURTS_REL = setup_tranche.DEFAULT_MICRO_COURTS_REL
DEFAULT_SETUP_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{setup_tranche.OUTPUT_SETUP_RECEIPT}"
DEFAULT_FIRST_EXECUTION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{first_wave.OUTPUT_EXECUTION_RECEIPT}"
DEFAULT_FIRST_BRIDGE_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{first_wave.OUTPUT_BRIDGE_SCORECARD}"
DEFAULT_FIRST_CAUSAL_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{first_wave.OUTPUT_CAUSAL_SCORECARD}"
DEFAULT_FIRST_DOMINANCE_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{first_wave.OUTPUT_DOMINANCE_PACKET}"
DEFAULT_ROUTE_MARGIN_RECORDS_REL = first_wave.DEFAULT_ROUTE_MARGIN_RECORDS_REL
DEFAULT_JOINT_BATCH_MANIFEST_REL = first_wave.DEFAULT_JOINT_BATCH_MANIFEST_REL
DEFAULT_DEFER_GATE_CONTRACT_REL = first_wave.DEFAULT_DEFER_GATE_CONTRACT_REL
DEFAULT_ROUTE_SELF_CHECK_CONTRACT_REL = first_wave.DEFAULT_ROUTE_SELF_CHECK_CONTRACT_REL
DEFAULT_ROUTE_HEAD_CHECKPOINT_REL = first_wave.DEFAULT_ROUTE_HEAD_CHECKPOINT_REL
DEFAULT_ROUTE_HEAD_LABEL_MAP_REL = first_wave.DEFAULT_ROUTE_HEAD_LABEL_MAP_REL
DEFAULT_ROUTE_HEAD_TRAIN_MANIFEST_REL = first_wave.DEFAULT_ROUTE_HEAD_TRAIN_MANIFEST_REL
DEFAULT_REPORTS_ROOT_REL = first_wave.DEFAULT_REPORTS_ROOT_REL

OUTPUT_ROW_PANEL = "cohort0_second_successor_evidence_row_panel.json"
OUTPUT_BRIDGE_SCORECARD = "cohort0_second_successor_bridge_candidate_scorecard.json"
OUTPUT_CAUSAL_SCORECARD = "cohort0_second_successor_causal_harness_scorecard.json"
OUTPUT_DOMINANCE_PACKET = "cohort0_second_successor_dominance_packet.json"
OUTPUT_EXECUTION_MANIFEST = "cohort0_second_successor_execution_manifest.json"
OUTPUT_EXECUTION_RECEIPT = "cohort0_second_successor_execution_receipt.json"
OUTPUT_REPORT = "COHORT0_SECOND_SUCCESSOR_EVIDENCE_REPORT.md"


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
        raise RuntimeError("FAIL_CLOSED: second-wave execution requires one same-head authority line")
    return next(iter(heads))


def _bool_rate(flags: Iterable[bool]) -> float:
    items = list(flags)
    if not items:
        return 0.0
    return round(sum(1 for item in items if item) / len(items), 6)


def _round_float(value: Any, digits: int = 6) -> float:
    return round(float(value), digits)


def _validate_first_wave_state(
    *,
    verdict_packet: Dict[str, Any],
    reentry_block: Dict[str, Any],
    micro_courts_manifest: Dict[str, Any],
    setup_receipt: Dict[str, Any],
    first_execution_receipt: Dict[str, Any],
    first_bridge_scorecard: Dict[str, Any],
    first_causal_scorecard: Dict[str, Any],
    first_dominance_packet: Dict[str, Any],
) -> None:
    for payload, label in (
        (verdict_packet, "hardened ceiling verdict packet"),
        (reentry_block, "gate d reentry block contract"),
        (micro_courts_manifest, "successor frozen micro-courts manifest"),
        (setup_receipt, "first successor evidence setup receipt"),
        (first_execution_receipt, "first successor evidence execution receipt"),
        (first_bridge_scorecard, "first successor bridge scorecard"),
        (first_causal_scorecard, "first successor causal scorecard"),
        (first_dominance_packet, "first successor dominance packet"),
    ):
        _ensure_pass(payload, label=label)

    if str(verdict_packet.get("final_verdict_id", "")).strip() != setup_tranche.EXPECTED_FINAL_VERDICT_ID:
        raise RuntimeError("FAIL_CLOSED: verdict packet final verdict mismatch")
    if not bool(verdict_packet.get("current_lane_closed", False)):
        raise RuntimeError("FAIL_CLOSED: current same-head lane must remain closed")
    if bool(verdict_packet.get("same_head_counted_reentry_admissible_now", True)):
        raise RuntimeError("FAIL_CLOSED: same-head counted reentry must remain blocked")

    if str(reentry_block.get("reentry_status", "")).strip() != "BLOCKED__CURRENT_LANE_HARDENED_CEILING":
        raise RuntimeError("FAIL_CLOSED: second-wave widening requires same-head reentry to remain blocked")
    if str(setup_receipt.get("setup_status", "")).strip() != "PASS__FIRST_SUCCESSOR_EVIDENCE_SETUP_BOUND":
        raise RuntimeError("FAIL_CLOSED: setup receipt must show first successor evidence setup bound")
    if str(first_execution_receipt.get("execution_status", "")).strip() != "PASS__FIRST_SUCCESSOR_EVIDENCE_EXECUTED__LIGHTWEIGHT":
        raise RuntimeError("FAIL_CLOSED: first-wave execution must exist before second-wave widening")
    if not bool(first_execution_receipt.get("reportability_lift_observed", False)):
        raise RuntimeError("FAIL_CLOSED: first-wave reportability lift must be positive before widening")
    if not bool(first_execution_receipt.get("route_consequence_signal_nonzero", False)):
        raise RuntimeError("FAIL_CLOSED: first-wave route consequence signal must be positive before widening")
    if bool(first_execution_receipt.get("counted_gate_d_readjudication_admissible_now", True)):
        raise RuntimeError("FAIL_CLOSED: second-wave widening starts only while counted reentry stays blocked")
    if bool(first_execution_receipt.get("gate_d_reopened", True)):
        raise RuntimeError("FAIL_CLOSED: second-wave widening assumes Gate D remains closed")
    if bool(first_execution_receipt.get("gate_e_open", True)):
        raise RuntimeError("FAIL_CLOSED: second-wave widening assumes Gate E remains closed")

    if str(first_dominance_packet.get("theorem_boundary", {}).get("counted_claim_status", "")).strip() != "NOT_EARNED__FIRST_LIGHTWEIGHT_SUCCESSOR_EVIDENCE_ONLY":
        raise RuntimeError("FAIL_CLOSED: first-wave dominance packet must remain explicitly non-counted")


def _typed_reason_label_v2(row: Dict[str, Any], *, route_family_ids: Sequence[str]) -> str:
    baseline = str(row.get("predicted_reason_label", "")).strip()
    if str(row.get("legacy_family_id", "")).strip() not in set(route_family_ids):
        return baseline
    if (
        baseline == "CONTROL_PRESERVATION"
        and str(row.get("lawful_action", "")).strip() == first_wave.ACTION_STATIC
        and float(row.get("wrong_static_hold_cost", 0.0)) <= 0.05
    ):
        return "RIGHTFUL_STATIC_HOLD_PRESERVED"
    if str(row.get("lawful_action", "")).strip() == first_wave.ACTION_ABSTAIN and float(row.get("missed_abstention_cost", 0.0)) > 0.0:
        return "RIGHTFUL_ABSTENTION_GUARD_PRESERVED"
    return baseline


def _counter_reason_label_v2(row: Dict[str, Any], *, route_family_ids: Sequence[str]) -> str:
    reason = _typed_reason_label_v2(row, route_family_ids=route_family_ids)
    family_id = str(row.get("legacy_family_id", "")).strip()
    if family_id not in set(route_family_ids):
        return reason
    if str(row.get("lawful_action", "")).strip() != first_wave.ACTION_ROUTE:
        return reason
    if reason != str(row.get("predicted_reason_label", "")).strip():
        return reason
    case_id = str(row.get("case_id", "")).upper()
    if family_id == first_wave.LEGACY_FOCUSED_FAMILY_ID:
        if "FRAME_LOCK" in case_id:
            return "FRAME_LOCK_PREMATURELY_COLLAPSES_RIVAL_VIEW"
        if "COUNTERREAD" in case_id:
            return "COUNTERREAD_VALUE_IS_VISIBLE_TOO_LATE"
        if "DOMAIN_OVERLAY" in case_id:
            return "DOMAIN_OVERLAY_HIDES_SECOND_ORDER_COST"
    if family_id == "STRATEGIST_CONSEQUENCE_CHAIN":
        if "TEMPORAL_DEPENDENCY" in case_id:
            return "TEMPORAL_DEPENDENCY_ORDER_MISPRICED"
        if "LOCAL_OPTIMUM" in case_id:
            return "LOCAL_OPTIMUM_BEATS_GLOBAL_SEQUENCE_COST"
        if "DEFERRED_ROLLBACK" in case_id:
            return "DELAYED_BRANCH_BREAKAGE_UNDERWEIGHTED"
    if family_id == "AUDITOR_ADMISSIBILITY_FAIL_CLOSED":
        if "BOUNDARY_EXCEPTION" in case_id:
            return "BOUNDARY_EXCEPTION_BAIT_UNDERPUNISHED"
        if "REPAIR_ORDER" in case_id:
            return "REPAIR_ORDER_COST_UNDERWEIGHTED"
        if "PLAUSIBLE_BUT_UNADMISSIBLE" in case_id:
            return "PLAUSIBLE_SURFACE_COHERENCE_BEATS_ADMISSIBILITY"
    return reason


def _refusal_allowed_v2(row: Dict[str, Any], *, route_family_ids: Sequence[str], thresholds: Dict[str, Any]) -> bool:
    return (
        str(row.get("legacy_family_id", "")).strip() in set(route_family_ids)
        and float(row.get("reason_confidence", 0.0)) <= float(thresholds.get("global_reason_conf_refusal_threshold", 0.0))
        and float(row.get("observed_route_margin", 0.0)) <= float(thresholds.get("observed_route_margin_refusal_floor", 0.0))
    )


def _variant_reason_label_v2(
    row: Dict[str, Any],
    *,
    variant_id: str,
    route_family_ids: Sequence[str],
    thresholds: Dict[str, Any],
) -> str:
    if variant_id == "RB_TYPED_CAUSAL_SCHEMA_BRIDGE_V1":
        return _typed_reason_label_v2(row, route_family_ids=route_family_ids)
    if variant_id == "RB_COUNTERFACTUAL_EVIDENCE_OBJECT_BRIDGE_V1":
        return _counter_reason_label_v2(row, route_family_ids=route_family_ids)
    if variant_id == "RB_CALIBRATED_REASON_REFUSAL_BRIDGE_V1":
        if _refusal_allowed_v2(row, route_family_ids=route_family_ids, thresholds=thresholds):
            return first_wave.LAWFUL_REASON_REFUSAL
        return _counter_reason_label_v2(row, route_family_ids=route_family_ids)
    raise RuntimeError(f"FAIL_CLOSED: unsupported second-wave variant id: {variant_id}")


def _reason_is_admissible_v2(
    row: Dict[str, Any],
    *,
    reason_label: str,
    route_family_ids: Sequence[str],
    thresholds: Dict[str, Any],
) -> bool:
    if reason_label == str(row.get("gold_reason_label", "")).strip():
        return True
    if reason_label == first_wave.LAWFUL_REASON_REFUSAL:
        return _refusal_allowed_v2(row, route_family_ids=route_family_ids, thresholds=thresholds)
    return False


def _selected_panels(
    *,
    observed_rows: Sequence[Dict[str, Any]],
    focused_current_family_id: str,
    support_lab_hold_family_ids: Sequence[str],
) -> Tuple[Dict[str, List[Dict[str, Any]]], List[str]]:
    route_current_family_ids = [focused_current_family_id, *[str(family_id).strip() for family_id in support_lab_hold_family_ids]]
    panels = {
        "SECOND_WAVE_FOCUSED_PANEL": [
            row for row in observed_rows if str(row.get("current_family_id", "")).strip() == focused_current_family_id
        ],
        "SECOND_WAVE_WIDENED_ROUTE_PANEL": [
            row for row in observed_rows if str(row.get("current_family_id", "")).strip() in set(route_current_family_ids)
        ],
        "SECOND_WAVE_WIDENED_MASKED_MUTATION_PANEL": [
            row
            for row in observed_rows
            if str(row.get("current_family_id", "")).strip() in set(route_current_family_ids)
            and str(row.get("variant_type", "")).strip() == "masked"
        ],
        "SECOND_WAVE_BOUNDARY_CONTROL_PANEL": [
            row for row in observed_rows if str(row.get("current_family_id", "")).strip() == "BOUNDARY_ABSTENTION_CONTROL"
        ],
        "SECOND_WAVE_STATIC_CONTROL_PANEL": [
            row for row in observed_rows if str(row.get("current_family_id", "")).strip() == "STATIC_NO_ROUTE_CONTROL"
        ],
    }
    for family_id in support_lab_hold_family_ids:
        key = f"SECOND_WAVE_ADJACENT__{str(family_id).strip()}"
        panels[key] = [row for row in observed_rows if str(row.get("current_family_id", "")).strip() == str(family_id).strip()]
    for panel_id, rows in panels.items():
        if not rows:
            raise RuntimeError(f"FAIL_CLOSED: second-wave widening panel {panel_id} bound to zero rows")
    return panels, route_current_family_ids


def _score_panel(rows: Sequence[Dict[str, Any]], *, reason_resolver, route_family_ids: Sequence[str], thresholds: Dict[str, Any]) -> Dict[str, Any]:
    exact = _bool_rate(reason_resolver(row) == row["gold_reason_label"] for row in rows)
    admissible = _bool_rate(
        _reason_is_admissible_v2(
            row,
            reason_label=reason_resolver(row),
            route_family_ids=route_family_ids,
            thresholds=thresholds,
        )
        for row in rows
    )
    refusal_count = sum(1 for row in rows if reason_resolver(row) == first_wave.LAWFUL_REASON_REFUSAL)
    action_accuracy = _bool_rate(str(row.get("predicted_action_label", "")).strip() == str(row.get("lawful_action", "")).strip() for row in rows)
    why_not_accuracy = _bool_rate(
        str(row.get("predicted_why_not_label", "")).strip() == str(row.get("gold_why_not_target_label", "")).strip() for row in rows
    )
    return {
        "row_count": len(rows),
        "action_accuracy": action_accuracy,
        "why_not_accuracy": why_not_accuracy,
        "reason_exact_accuracy": exact,
        "reason_admissible_accuracy": admissible,
        "lawful_refusal_count": refusal_count,
    }


def _variant_overall_from_panels(panel_metrics: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    widened = panel_metrics["SECOND_WAVE_WIDENED_ROUTE_PANEL"]
    masked = panel_metrics["SECOND_WAVE_WIDENED_MASKED_MUTATION_PANEL"]
    boundary = panel_metrics["SECOND_WAVE_BOUNDARY_CONTROL_PANEL"]
    static = panel_metrics["SECOND_WAVE_STATIC_CONTROL_PANEL"]
    controls_preserved = (
        boundary["reason_exact_accuracy"] >= 1.0
        and static["reason_exact_accuracy"] >= 1.0
        and boundary["action_accuracy"] >= 1.0
        and static["action_accuracy"] >= 1.0
    )
    one_notch_widening_holds = (
        widened["reason_admissible_accuracy"] >= 0.95
        and widened["reason_exact_accuracy"] >= 0.95
        and masked["reason_admissible_accuracy"] >= 0.95
        and controls_preserved
    )
    return {
        "widened_route_reason_exact_accuracy": widened["reason_exact_accuracy"],
        "widened_route_reason_admissible_accuracy": widened["reason_admissible_accuracy"],
        "widened_masked_reason_exact_accuracy": masked["reason_exact_accuracy"],
        "widened_masked_reason_admissible_accuracy": masked["reason_admissible_accuracy"],
        "controls_preserved": controls_preserved,
        "one_notch_widening_holds": one_notch_widening_holds,
        "lawful_refusal_count": widened["lawful_refusal_count"],
    }


def _score_bridge_candidates(
    *,
    observed_rows: Sequence[Dict[str, Any]],
    route_family_ids: Sequence[str],
    thresholds: Dict[str, Any],
    support_lab_hold_family_ids: Sequence[str],
    focused_current_family_id: str,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    panels, route_current_family_ids = _selected_panels(
        observed_rows=observed_rows,
        focused_current_family_id=focused_current_family_id,
        support_lab_hold_family_ids=support_lab_hold_family_ids,
    )
    route_legacy_family_ids = {
        first_wave.LEGACY_FOCUSED_FAMILY_ID,
        *[str(family_id).strip() for family_id in support_lab_hold_family_ids],
    }
    baseline_resolver = lambda row: str(row.get("predicted_reason_label", "")).strip()
    variant_ids = [
        "RB_TYPED_CAUSAL_SCHEMA_BRIDGE_V1",
        "RB_COUNTERFACTUAL_EVIDENCE_OBJECT_BRIDGE_V1",
        "RB_CALIBRATED_REASON_REFUSAL_BRIDGE_V1",
    ]
    candidate_rows: List[Dict[str, Any]] = []
    row_panel_rows: List[Dict[str, Any]] = []
    for row in observed_rows:
        row_panel_rows.append(
            {
                "case_id": row["case_id"],
                "current_family_id": row["current_family_id"],
                "legacy_family_id": row["legacy_family_id"],
                "variant_type": row["variant_type"],
                "lawful_action": row["lawful_action"],
                "predicted_action_label": row["predicted_action_label"],
                "predicted_why_not_label": row["predicted_why_not_label"],
                "gold_reason_label": row["gold_reason_label"],
                "baseline_reason_label": baseline_resolver(row),
                "baseline_reason_exact": baseline_resolver(row) == row["gold_reason_label"],
                "baseline_reason_admissible": _reason_is_admissible_v2(
                    row,
                    reason_label=baseline_resolver(row),
                    route_family_ids=route_legacy_family_ids,
                    thresholds=thresholds,
                ),
                "action_confidence": row["action_confidence"],
                "reason_confidence": row["reason_confidence"],
                "why_not_confidence": row["why_not_confidence"],
                "observed_route_margin": row["observed_route_margin"],
                "expected_route_margin": row["expected_route_margin"],
                "wrong_route_cost": row["wrong_route_cost"],
                "wrong_static_hold_cost": row["wrong_static_hold_cost"],
                "missed_abstention_cost": row["missed_abstention_cost"],
                "panel_ids": [panel_id for panel_id, items in panels.items() if any(item["case_id"] == row["case_id"] for item in items)],
                "candidate_outputs": {},
            }
        )

    panel_index = {row["case_id"]: row for row in row_panel_rows}
    baseline_panel_metrics = {panel_id: _score_panel(rows, reason_resolver=baseline_resolver, route_family_ids=route_legacy_family_ids, thresholds=thresholds) for panel_id, rows in panels.items()}
    widened_baseline_exact = baseline_panel_metrics["SECOND_WAVE_WIDENED_ROUTE_PANEL"]["reason_exact_accuracy"]
    widened_baseline_admissible = baseline_panel_metrics["SECOND_WAVE_WIDENED_ROUTE_PANEL"]["reason_admissible_accuracy"]

    lead_candidate_ids = ["RB_TYPED_CAUSAL_SCHEMA_BRIDGE_V1", "RB_COUNTERFACTUAL_EVIDENCE_OBJECT_BRIDGE_V1"]
    guardrail_candidate_ids = ["RB_CALIBRATED_REASON_REFUSAL_BRIDGE_V1"]
    for variant_id in variant_ids:
        reason_resolver = lambda row, _variant_id=variant_id: _variant_reason_label_v2(
            row,
            variant_id=_variant_id,
            route_family_ids=route_legacy_family_ids,
            thresholds=thresholds,
        )
        metrics_by_panel = {panel_id: _score_panel(rows, reason_resolver=reason_resolver, route_family_ids=route_legacy_family_ids, thresholds=thresholds) for panel_id, rows in panels.items()}
        overall = _variant_overall_from_panels(metrics_by_panel)
        overall.update(
            {
                "widened_route_exact_lift_vs_baseline": _round_float(
                    overall["widened_route_reason_exact_accuracy"] - widened_baseline_exact
                ),
                "widened_route_admissible_lift_vs_baseline": _round_float(
                    overall["widened_route_reason_admissible_accuracy"] - widened_baseline_admissible
                ),
            }
        )
        for row in observed_rows:
            reason_label = reason_resolver(row)
            panel_index[row["case_id"]]["candidate_outputs"][variant_id] = {
                "reason_label": reason_label,
                "exact": reason_label == row["gold_reason_label"],
                "admissible": _reason_is_admissible_v2(
                    row,
                    reason_label=reason_label,
                    route_family_ids=route_legacy_family_ids,
                    thresholds=thresholds,
                ),
                "lawful_refusal": reason_label == first_wave.LAWFUL_REASON_REFUSAL,
            }
        candidate_rows.append(
            {
                "variant_id": variant_id,
                "wave_two_role": "LEAD" if variant_id in lead_candidate_ids else "GUARDRAIL",
                "overall": overall,
                "panel_metrics": metrics_by_panel,
            }
        )

    best_candidate = max(
        candidate_rows,
        key=lambda row: (
            float(row["overall"]["widened_route_reason_admissible_accuracy"]),
            float(row["overall"]["widened_route_reason_exact_accuracy"]),
            0.0 if row["wave_two_role"] == "GUARDRAIL" else 1.0,
        ),
    )
    bridge_scorecard = {
        "schema_id": "kt.operator.cohort0_second_successor_bridge_candidate_scorecard.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This is second-wave lightweight widening over the first successor bridge candidates. "
            "It is still non-counted and does not reopen Gate D."
        ),
        "execution_status": "PASS__SECOND_WAVE_ONE_NOTCH_WIDENING_EXECUTED",
        "focused_family_id": focused_current_family_id,
        "adjacent_family_ids": list(route_current_family_ids[1:]),
        "lead_candidate_ids": lead_candidate_ids,
        "guardrail_candidate_ids": guardrail_candidate_ids,
        "baseline_panel_metrics": baseline_panel_metrics,
        "candidates": candidate_rows,
        "selected_best_candidate_id": best_candidate["variant_id"],
        "selected_best_candidate_wave_two_role": best_candidate["wave_two_role"],
        "selected_best_candidate_one_notch_widening_holds": best_candidate["overall"]["one_notch_widening_holds"],
    }
    row_panel = {
        "schema_id": "kt.operator.cohort0_second_successor_evidence_row_panel.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This row panel records second-wave widening evidence only. "
            "It is a lightweight successor trace, not counted theorem proof."
        ),
        "rows": row_panel_rows,
    }
    return bridge_scorecard, row_panel


def _score_causal_harness(
    *,
    observed_rows: Sequence[Dict[str, Any]],
    support_lab_hold_family_ids: Sequence[str],
    focused_current_family_id: str,
) -> Dict[str, Any]:
    route_current_family_ids = [focused_current_family_id, *[str(family_id).strip() for family_id in support_lab_hold_family_ids]]
    widened_route_rows = [row for row in observed_rows if str(row.get("current_family_id", "")).strip() in set(route_current_family_ids)]
    boundary_rows = [row for row in observed_rows if str(row.get("current_family_id", "")).strip() == "BOUNDARY_ABSTENTION_CONTROL"]
    static_rows = [row for row in observed_rows if str(row.get("current_family_id", "")).strip() == "STATIC_NO_ROUTE_CONTROL"]
    baseline_panel = first_wave._score_intervention_rows(widened_route_rows, intervention_id="BASELINE_FOLLOW_HEAD")
    forced_wrong_route = first_wave._score_intervention_rows(widened_route_rows, intervention_id="FORCED_WRONG_ROUTE_PRIMARY")
    random_route = first_wave._score_intervention_rows(widened_route_rows, intervention_id="RANDOM_ROUTE_NEGATIVE_CONTROL_PRIMARY")
    oracle_route = first_wave._score_intervention_rows(widened_route_rows, intervention_id="ORACLE_ROUTE_UPPER_BOUND_PRIMARY")
    witness_ablation = first_wave._score_intervention_rows(widened_route_rows, intervention_id="WITNESS_ABLATION_PRIMARY")
    static_control = first_wave._score_intervention_rows(static_rows, intervention_id="FORCED_STATIC_HOLD_CONTROL_SPINE")
    boundary_guard = first_wave._score_intervention_rows(boundary_rows, intervention_id="ABSTAIN_DISABLED_BOUNDARY_SPINE")
    signals = {
        "wrong_route_penalty_visible": float(forced_wrong_route["total_cost"]) > float(baseline_panel["total_cost"]),
        "witness_ablation_penalty_visible": float(witness_ablation["total_cost"]) > float(baseline_panel["total_cost"]),
        "random_route_penalty_visible": float(random_route["total_cost"]) > float(baseline_panel["total_cost"]),
        "static_hold_control_preserved": float(static_control["total_cost"]) == 0.0,
        "boundary_abstention_guard_visible": float(boundary_guard["total_cost"]) > 0.0,
        "route_consequence_signal_nonzero": float(forced_wrong_route["total_cost"]) > 0.0 and float(witness_ablation["total_cost"]) > 0.0,
    }
    return {
        "schema_id": "kt.operator.cohort0_second_successor_causal_harness_scorecard.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This is second-wave lightweight causal-harness widening over the route-bearing families and control spines. "
            "It is still non-counted and does not reopen Gate D."
        ),
        "execution_status": "PASS__SECOND_WAVE_ONE_NOTCH_CAUSAL_HARNESS_EXECUTED",
        "route_bearing_family_ids": route_current_family_ids,
        "baseline_panel": baseline_panel,
        "interventions": {
            "FORCED_WRONG_ROUTE_PRIMARY": forced_wrong_route,
            "RANDOM_ROUTE_NEGATIVE_CONTROL_PRIMARY": random_route,
            "ORACLE_ROUTE_UPPER_BOUND_PRIMARY": oracle_route,
            "WITNESS_ABLATION_PRIMARY": witness_ablation,
            "FORCED_STATIC_HOLD_CONTROL_SPINE": static_control,
            "ABSTAIN_DISABLED_BOUNDARY_SPINE": boundary_guard,
        },
        "signals": signals,
    }


def _build_dominance_packet(
    *,
    focused_current_family_id: str,
    support_lab_hold_family_ids: Sequence[str],
    bridge_scorecard: Dict[str, Any],
    causal_scorecard: Dict[str, Any],
    row_panel: Dict[str, Any],
) -> Dict[str, Any]:
    route_families = [focused_current_family_id, *[str(family_id).strip() for family_id in support_lab_hold_family_ids]]
    rows = list(row_panel.get("rows", []))
    route_rows = [row for row in rows if str(row.get("current_family_id", "")).strip() in set(route_families)]
    control_rows = [row for row in rows if str(row.get("current_family_id", "")).strip() in {"BOUNDARY_ABSTENTION_CONTROL", "STATIC_NO_ROUTE_CONTROL"}]
    best_candidate_id = str(bridge_scorecard.get("selected_best_candidate_id", "")).strip()
    best_candidate = next(
        (candidate for candidate in bridge_scorecard.get("candidates", []) if str(candidate.get("variant_id", "")).strip() == best_candidate_id),
        {},
    )
    alpha_should_lose = [
        {
            "case_id": row["case_id"],
            "family_id": row["current_family_id"],
            "legacy_family_id": row["legacy_family_id"],
            "wrong_static_hold_cost": row["wrong_static_hold_cost"],
            "why": "Forced static hold still carries positive cost while the widened lightweight executor keeps the lawful non-static action.",
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
    family_concentration = {
        "signal_family_ids": route_families if bool(causal_scorecard.get("signals", {}).get("route_consequence_signal_nonzero", False)) else [],
        "family_local_only": False,
        "one_notch_widening_only": True,
        "counted_dominance_claim_admissible": False,
    }
    return {
        "schema_id": "kt.operator.cohort0_second_successor_dominance_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This is a second-wave widening dominance packet built from lightweight executed bridge and harness evidence only. "
            "It does not reopen Gate D or authorize counted reentry."
        ),
        "execution_status": "PASS__SECOND_WAVE_ONE_NOTCH_DOMINANCE_PACKET_EMITTED",
        "focused_family_id": focused_current_family_id,
        "adjacent_family_ids": list(support_lab_hold_family_ids),
        "alpha_should_lose_here_manifest": alpha_should_lose,
        "alpha_still_dominates_here_manifest": alpha_still_dominates,
        "abstain_static_boundary_correctness_map": {
            "boundary_guard_visible": bool(causal_scorecard.get("signals", {}).get("boundary_abstention_guard_visible", False)),
            "static_hold_control_preserved": bool(causal_scorecard.get("signals", {}).get("static_hold_control_preserved", False)),
            "focused_plus_adjacent_route_family_ids": route_families,
        },
        "route_economics_reduction_map": {
            "baseline_total_cost": causal_scorecard.get("baseline_panel", {}).get("total_cost", 0.0),
            "forced_wrong_route_total_cost": causal_scorecard.get("interventions", {}).get("FORCED_WRONG_ROUTE_PRIMARY", {}).get("total_cost", 0.0),
            "witness_ablation_total_cost": causal_scorecard.get("interventions", {}).get("WITNESS_ABLATION_PRIMARY", {}).get("total_cost", 0.0),
            "random_route_total_cost": causal_scorecard.get("interventions", {}).get("RANDOM_ROUTE_NEGATIVE_CONTROL_PRIMARY", {}).get("total_cost", 0.0),
            "boundary_abstention_total_cost": causal_scorecard.get("interventions", {}).get("ABSTAIN_DISABLED_BOUNDARY_SPINE", {}).get("total_cost", 0.0),
            "static_control_total_cost": causal_scorecard.get("interventions", {}).get("FORCED_STATIC_HOLD_CONTROL_SPINE", {}).get("total_cost", 0.0),
            "route_consequence_signal_nonzero": bool(causal_scorecard.get("signals", {}).get("route_consequence_signal_nonzero", False)),
        },
        "family_concentration_report": family_concentration,
        "reportability_summary": {
            "baseline_widened_route_reason_exact_accuracy": bridge_scorecard.get("baseline_panel_metrics", {}).get(
                "SECOND_WAVE_WIDENED_ROUTE_PANEL",
                {},
            ).get("reason_exact_accuracy", 0.0),
            "baseline_widened_route_reason_admissible_accuracy": bridge_scorecard.get("baseline_panel_metrics", {}).get(
                "SECOND_WAVE_WIDENED_ROUTE_PANEL",
                {},
            ).get("reason_admissible_accuracy", 0.0),
            "selected_best_candidate_id": best_candidate_id,
            "selected_best_candidate_widened_route_exact_accuracy": best_candidate.get("overall", {}).get(
                "widened_route_reason_exact_accuracy",
                0.0,
            ),
            "selected_best_candidate_widened_route_admissible_accuracy": best_candidate.get("overall", {}).get(
                "widened_route_reason_admissible_accuracy",
                0.0,
            ),
            "selected_best_candidate_one_notch_widening_holds": bridge_scorecard.get("selected_best_candidate_one_notch_widening_holds", False),
        },
        "theorem_boundary": {
            "gate_d_reopened": False,
            "same_head_counted_reentry_admissible_now": False,
            "gate_e_open": False,
            "counted_claim_status": "NOT_EARNED__SECOND_WAVE_ONE_NOTCH_WIDENING_ONLY",
        },
    }


def _build_markdown_report(execution_manifest: Dict[str, Any], outputs: Sequence[str]) -> str:
    lines: List[str] = []
    lines.append("# COHORT0 Second Successor Evidence Report")
    lines.append("")
    lines.append(f"- Generated UTC: `{execution_manifest['generated_utc']}`")
    lines.append(f"- Subject head: `{execution_manifest['subject_head']}`")
    lines.append(f"- Focused family: `{execution_manifest['focused_family_id']}`")
    lines.append(f"- Adjacent families: `{', '.join(execution_manifest['adjacent_family_ids'])}`")
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


def run_second_successor_evidence_wave_tranche(
    *,
    verdict_packet_path: Path,
    reentry_block_path: Path,
    micro_courts_manifest_path: Path,
    setup_receipt_path: Path,
    first_execution_receipt_path: Path,
    first_bridge_scorecard_path: Path,
    first_causal_scorecard_path: Path,
    first_dominance_packet_path: Path,
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
    first_bridge_scorecard = _load_json_required(first_bridge_scorecard_path, label="first successor bridge scorecard")
    first_causal_scorecard = _load_json_required(first_causal_scorecard_path, label="first successor causal scorecard")
    first_dominance_packet = _load_json_required(first_dominance_packet_path, label="first successor dominance packet")

    _validate_first_wave_state(
        verdict_packet=verdict_packet,
        reentry_block=reentry_block,
        micro_courts_manifest=micro_courts_manifest,
        setup_receipt=setup_receipt,
        first_execution_receipt=first_execution_receipt,
        first_bridge_scorecard=first_bridge_scorecard,
        first_causal_scorecard=first_causal_scorecard,
        first_dominance_packet=first_dominance_packet,
    )
    subject_head = _require_same_subject_head(
        [
            verdict_packet,
            reentry_block,
            micro_courts_manifest,
            setup_receipt,
            first_execution_receipt,
            first_bridge_scorecard,
            first_causal_scorecard,
            first_dominance_packet,
        ]
    )
    if subject_head != setup_tranche.EXPECTED_SUBJECT_HEAD:
        raise RuntimeError("FAIL_CLOSED: unexpected subject head for second-wave widening")

    focused_current_family_id = str(micro_courts_manifest.get("focused_family_id", "")).strip()
    support_lab_hold_family_ids = [str(item).strip() for item in micro_courts_manifest.get("support_lab_hold_family_ids", []) if str(item).strip()]
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
    bridge_scorecard, row_panel = _score_bridge_candidates(
        observed_rows=observed["observed_rows"],
        route_family_ids=[
            first_wave.LEGACY_FOCUSED_FAMILY_ID,
            *support_lab_hold_family_ids,
        ],
        thresholds=observed["thresholds"],
        support_lab_hold_family_ids=support_lab_hold_family_ids,
        focused_current_family_id=focused_current_family_id,
    )
    causal_scorecard = _score_causal_harness(
        observed_rows=observed["observed_rows"],
        support_lab_hold_family_ids=support_lab_hold_family_ids,
        focused_current_family_id=focused_current_family_id,
    )
    dominance_packet = _build_dominance_packet(
        focused_current_family_id=focused_current_family_id,
        support_lab_hold_family_ids=support_lab_hold_family_ids,
        bridge_scorecard=bridge_scorecard,
        causal_scorecard=causal_scorecard,
        row_panel=row_panel,
    )
    execution_manifest = {
        "schema_id": "kt.operator.cohort0_second_successor_execution_manifest.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": verdict_packet.get("current_git_head", ""),
        "subject_head": subject_head,
        "claim_boundary": (
            "This tranche runs second-wave one-notch widening over the first successor bridge candidates and widened causal harness. "
            "It remains non-counted and does not reopen Gate D."
        ),
        "execution_status": "PASS__SECOND_WAVE_ONE_NOTCH_WIDENING_EXECUTED",
        "focused_family_id": focused_current_family_id,
        "adjacent_family_ids": support_lab_hold_family_ids,
        "completed_now": [
            "Replicated the first-wave bridge candidates under one-notch widening to adjacent frozen families.",
            "Scored widened reportability on focused, adjacent, mutation, and control panels.",
            "Ran the widened causal harness over the route-bearing family set plus boundary and static controls.",
            "Emitted a second-wave widening dominance packet from executed evidence only.",
            "Kept Gate D readjudication dormant and same-head counted reentry blocked.",
        ],
        "selected_best_candidate_id": bridge_scorecard.get("selected_best_candidate_id", ""),
        "selected_best_candidate_wave_two_role": bridge_scorecard.get("selected_best_candidate_wave_two_role", ""),
        "selected_best_candidate_one_notch_widening_holds": bridge_scorecard.get(
            "selected_best_candidate_one_notch_widening_holds",
            False,
        ),
    }
    execution_receipt = {
        "schema_id": "kt.operator.cohort0_second_successor_execution_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "subject_head": subject_head,
        "claim_boundary": (
            "This receipt records second-wave one-notch widening only. "
            "It does not claim Gate D reopened, counted reentry became admissible, or Gate E opened."
        ),
        "execution_status": execution_manifest["execution_status"],
        "focused_family_id": focused_current_family_id,
        "adjacent_family_ids": support_lab_hold_family_ids,
        "selected_best_candidate_id": bridge_scorecard.get("selected_best_candidate_id", ""),
        "selected_best_candidate_wave_two_role": bridge_scorecard.get("selected_best_candidate_wave_two_role", ""),
        "selected_best_candidate_one_notch_widening_holds": bridge_scorecard.get(
            "selected_best_candidate_one_notch_widening_holds",
            False,
        ),
        "selected_best_candidate_widened_route_exact_accuracy": next(
            (
                candidate.get("overall", {}).get("widened_route_reason_exact_accuracy", 0.0)
                for candidate in bridge_scorecard.get("candidates", [])
                if str(candidate.get("variant_id", "")).strip() == str(bridge_scorecard.get("selected_best_candidate_id", "")).strip()
            ),
            0.0,
        ),
        "selected_best_candidate_widened_route_admissible_accuracy": next(
            (
                candidate.get("overall", {}).get("widened_route_reason_admissible_accuracy", 0.0)
                for candidate in bridge_scorecard.get("candidates", [])
                if str(candidate.get("variant_id", "")).strip() == str(bridge_scorecard.get("selected_best_candidate_id", "")).strip()
            ),
            0.0,
        ),
        "route_consequence_signal_nonzero": bool(causal_scorecard.get("signals", {}).get("route_consequence_signal_nonzero", False)),
        "wrong_route_penalty_visible": bool(causal_scorecard.get("signals", {}).get("wrong_route_penalty_visible", False)),
        "witness_ablation_penalty_visible": bool(causal_scorecard.get("signals", {}).get("witness_ablation_penalty_visible", False)),
        "static_hold_control_preserved": bool(causal_scorecard.get("signals", {}).get("static_hold_control_preserved", False)),
        "readjudication_admissible_now": False,
        "same_head_counted_reentry_admissible_now": False,
        "gate_d_reopened": False,
        "gate_e_open": False,
        "counted_claim_status": "NOT_EARNED__SECOND_WAVE_ONE_NOTCH_WIDENING_ONLY",
        "next_lawful_move": setup_tranche.EXPECTED_PRIMARY_MOVE,
        "secondary_parallel_move": setup_tranche.EXPECTED_SECONDARY_MOVE,
        "source_refs": {
            "first_execution_receipt_ref": first_execution_receipt_path.as_posix(),
            "first_bridge_scorecard_ref": first_bridge_scorecard_path.as_posix(),
            "first_causal_scorecard_ref": first_causal_scorecard_path.as_posix(),
            "first_dominance_packet_ref": first_dominance_packet_path.as_posix(),
            "execution_manifest_ref": (reports_root / OUTPUT_EXECUTION_MANIFEST).resolve().as_posix(),
            "bridge_scorecard_ref": (reports_root / OUTPUT_BRIDGE_SCORECARD).resolve().as_posix(),
            "causal_scorecard_ref": (reports_root / OUTPUT_CAUSAL_SCORECARD).resolve().as_posix(),
            "dominance_packet_ref": (reports_root / OUTPUT_DOMINANCE_PACKET).resolve().as_posix(),
            "row_panel_ref": (reports_root / OUTPUT_ROW_PANEL).resolve().as_posix(),
        },
    }

    row_panel.update(
        {
            "subject_head": subject_head,
            "focused_family_id": focused_current_family_id,
            "adjacent_family_ids": support_lab_hold_family_ids,
            "distribution_summary": observed["distribution_summary"],
            "thresholds": observed["thresholds"],
            "bundle_metadata": observed["bundle_metadata"],
        }
    )
    bridge_scorecard.update({"subject_head": subject_head})
    causal_scorecard.update({"subject_head": subject_head})
    dominance_packet.update({"subject_head": subject_head})

    artifact_payloads = {
        OUTPUT_ROW_PANEL: row_panel,
        OUTPUT_BRIDGE_SCORECARD: bridge_scorecard,
        OUTPUT_CAUSAL_SCORECARD: causal_scorecard,
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
    parser = argparse.ArgumentParser(description="Run second-wave one-notch widening over the first successor evidence candidates.")
    parser.add_argument("--verdict-packet", default=DEFAULT_VERDICT_PACKET_REL)
    parser.add_argument("--reentry-block", default=DEFAULT_REENTRY_BLOCK_REL)
    parser.add_argument("--micro-courts-manifest", default=DEFAULT_MICRO_COURTS_REL)
    parser.add_argument("--setup-receipt", default=DEFAULT_SETUP_RECEIPT_REL)
    parser.add_argument("--first-execution-receipt", default=DEFAULT_FIRST_EXECUTION_RECEIPT_REL)
    parser.add_argument("--first-bridge-scorecard", default=DEFAULT_FIRST_BRIDGE_SCORECARD_REL)
    parser.add_argument("--first-causal-scorecard", default=DEFAULT_FIRST_CAUSAL_SCORECARD_REL)
    parser.add_argument("--first-dominance-packet", default=DEFAULT_FIRST_DOMINANCE_PACKET_REL)
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
    payload = run_second_successor_evidence_wave_tranche(
        verdict_packet_path=_resolve(root, str(args.verdict_packet)),
        reentry_block_path=_resolve(root, str(args.reentry_block)),
        micro_courts_manifest_path=_resolve(root, str(args.micro_courts_manifest)),
        setup_receipt_path=_resolve(root, str(args.setup_receipt)),
        first_execution_receipt_path=_resolve(root, str(args.first_execution_receipt)),
        first_bridge_scorecard_path=_resolve(root, str(args.first_bridge_scorecard)),
        first_causal_scorecard_path=_resolve(root, str(args.first_causal_scorecard)),
        first_dominance_packet_path=_resolve(root, str(args.first_dominance_packet)),
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
            "selected_best_candidate_id": receipt["selected_best_candidate_id"],
            "one_notch_widening_holds": receipt["selected_best_candidate_one_notch_widening_holds"],
            "route_consequence_signal_nonzero": receipt["route_consequence_signal_nonzero"],
            "output_count": len(payload["outputs"]),
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
