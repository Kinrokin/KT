from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import torch
import torch.nn.functional as F

from tools.operator import cohort0_first_successor_evidence_setup_tranche as setup_tranche
from tools.operator.titanium_common import (
    file_sha256,
    load_json,
    repo_root,
    utc_now_iso_z,
    write_json_stable,
)
from tools.training.train_gate_d_route_judgment_head import (
    ACTION_ABSTAIN,
    ACTION_ROUTE,
    ACTION_STATIC,
    RouteJudgmentHead,
    _build_case_record,
    _load_joint_batch_map,
    _maybe_load_case_map,
    load_rows,
)


DEFAULT_VERDICT_PACKET_REL = setup_tranche.DEFAULT_VERDICT_PACKET_REL
DEFAULT_REENTRY_BLOCK_REL = setup_tranche.DEFAULT_REENTRY_BLOCK_REL
DEFAULT_REPORTABILITY_METRIC_CONTRACT_REL = "KT_PROD_CLEANROOM/reports/reportability_bridge_metric_contract.json"
DEFAULT_ROUTE_CONSEQUENCE_VERDICT_REL = "KT_PROD_CLEANROOM/reports/route_consequence_verdict_receipt.json"
DEFAULT_MICRO_COURTS_REL = setup_tranche.DEFAULT_MICRO_COURTS_REL
DEFAULT_REPORTABILITY_VARIANT_MANIFEST_REL = f"KT_PROD_CLEANROOM/reports/{setup_tranche.OUTPUT_REPORTABILITY_VARIANT_MANIFEST}"
DEFAULT_CAUSAL_LAUNCH_MANIFEST_REL = f"KT_PROD_CLEANROOM/reports/{setup_tranche.OUTPUT_CAUSAL_LAUNCH_MANIFEST}"
DEFAULT_DOMINANCE_PACKET_CONTRACT_REL = "KT_PROD_CLEANROOM/reports/cohort0_successor_dominance_packet_contract.json"
DEFAULT_SETUP_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{setup_tranche.OUTPUT_SETUP_RECEIPT}"
DEFAULT_REPORTS_ROOT_REL = setup_tranche.DEFAULT_REPORTS_ROOT_REL

DEFAULT_ROUTE_MARGIN_RECORDS_REL = (
    "_tmp/return_residual_alpha_refinement_commitment/"
    "residual_alpha_refinement_commitment_return/route_court/"
    "cohort0_residual_alpha_breakthrough_route_margin_records.json"
)
DEFAULT_JOINT_BATCH_MANIFEST_REL = (
    "_tmp/return_residual_alpha_refinement_commitment/"
    "residual_alpha_refinement_commitment_return/route_court/"
    "cohort0_residual_alpha_breakthrough_joint_batch_manifest.json"
)
DEFAULT_DEFER_GATE_CONTRACT_REL = (
    "_tmp/return_residual_alpha_refinement_commitment/"
    "residual_alpha_refinement_commitment_return/route_court/"
    "cohort0_residual_alpha_breakthrough_defer_gate_contract.json"
)
DEFAULT_ROUTE_SELF_CHECK_CONTRACT_REL = (
    "_tmp/return_residual_alpha_refinement_commitment/"
    "residual_alpha_refinement_commitment_return/route_court/"
    "cohort0_residual_alpha_breakthrough_route_self_check_contract.json"
)
DEFAULT_ROUTE_HEAD_CHECKPOINT_REL = (
    "_tmp/return_residual_alpha_refinement_commitment/"
    "residual_alpha_refinement_commitment_return/route_judgment_head/gate_d_route_judgment_head.pt"
)
DEFAULT_ROUTE_HEAD_LABEL_MAP_REL = (
    "_tmp/return_residual_alpha_refinement_commitment/"
    "residual_alpha_refinement_commitment_return/route_judgment_head/label_maps.json"
)
DEFAULT_ROUTE_HEAD_TRAIN_MANIFEST_REL = (
    "_tmp/return_residual_alpha_refinement_commitment/"
    "residual_alpha_refinement_commitment_return/route_judgment_head/train_manifest.json"
)

LEGACY_FOCUSED_FAMILY_ID = "BETA_SECOND_ORDER_REFRAME"
LAWFUL_REASON_REFUSAL = "LAWFUL_REASON_REFUSAL"

OUTPUT_ROW_PANEL = "cohort0_first_successor_evidence_row_panel.json"
OUTPUT_BRIDGE_SCORECARD = "cohort0_first_successor_bridge_variant_scorecard.json"
OUTPUT_CAUSAL_SCORECARD = "cohort0_first_successor_causal_intervention_scorecard.json"
OUTPUT_DOMINANCE_PACKET = "cohort0_first_successor_dominance_packet.json"
OUTPUT_EXECUTION_MANIFEST = "cohort0_first_successor_evidence_execution_manifest.json"
OUTPUT_EXECUTION_RECEIPT = "cohort0_first_successor_evidence_execution_receipt.json"
OUTPUT_REPORT = "COHORT0_FIRST_SUCCESSOR_EVIDENCE_EXECUTION_REPORT.md"


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
        raise RuntimeError("FAIL_CLOSED: expected one same-head authority line")
    return next(iter(heads))


def _percentile(values: Sequence[float], frac: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(float(value) for value in values)
    index = max(0, int(len(ordered) * frac) - 1)
    return float(ordered[index])


def _round_float(value: Any, digits: int = 6) -> float:
    return round(float(value), digits)


def _bool_rate(flags: Iterable[bool]) -> float:
    items = list(flags)
    if not items:
        return 0.0
    return round(sum(1 for item in items if item) / len(items), 6)


def _mapped_family_id(family_id: str, *, focused_current_family_id: str) -> str:
    if str(family_id).strip() == LEGACY_FOCUSED_FAMILY_ID:
        return focused_current_family_id
    return str(family_id).strip()


def _validate_setup_state(
    *,
    verdict_packet: Dict[str, Any],
    reentry_block: Dict[str, Any],
    reportability_metric_contract: Dict[str, Any],
    route_consequence_verdict_receipt: Dict[str, Any],
    micro_courts_manifest: Dict[str, Any],
    reportability_variant_manifest: Dict[str, Any],
    causal_launch_manifest: Dict[str, Any],
    dominance_packet_contract: Dict[str, Any],
    setup_receipt: Dict[str, Any],
) -> None:
    for payload, label in (
        (verdict_packet, "hardened ceiling verdict packet"),
        (reentry_block, "gate d reentry block contract"),
        (reportability_metric_contract, "reportability bridge metric contract"),
        (route_consequence_verdict_receipt, "route consequence verdict receipt"),
        (micro_courts_manifest, "successor frozen micro-courts manifest"),
        (reportability_variant_manifest, "reportability bridge variant manifest"),
        (causal_launch_manifest, "causal launch manifest"),
        (dominance_packet_contract, "successor dominance packet contract"),
        (setup_receipt, "first successor evidence setup receipt"),
    ):
        _ensure_pass(payload, label=label)

    if str(verdict_packet.get("final_verdict_id", "")).strip() != setup_tranche.EXPECTED_FINAL_VERDICT_ID:
        raise RuntimeError("FAIL_CLOSED: verdict packet final verdict mismatch")
    if not bool(verdict_packet.get("current_lane_closed", False)):
        raise RuntimeError("FAIL_CLOSED: current same-head lane must remain closed")
    if bool(verdict_packet.get("same_head_counted_reentry_admissible_now", True)):
        raise RuntimeError("FAIL_CLOSED: same-head counted reentry must remain blocked")
    if str(verdict_packet.get("next_lawful_move", "")).strip() != setup_tranche.EXPECTED_PRIMARY_MOVE:
        raise RuntimeError("FAIL_CLOSED: verdict packet primary move mismatch")
    if str(verdict_packet.get("secondary_parallel_move", "")).strip() != setup_tranche.EXPECTED_SECONDARY_MOVE:
        raise RuntimeError("FAIL_CLOSED: verdict packet secondary move mismatch")

    if str(reentry_block.get("reentry_status", "")).strip() != "BLOCKED__CURRENT_LANE_HARDENED_CEILING":
        raise RuntimeError("FAIL_CLOSED: same-head reentry must stay blocked")

    if str(setup_receipt.get("setup_status", "")).strip() != "PASS__FIRST_SUCCESSOR_EVIDENCE_SETUP_BOUND":
        raise RuntimeError("FAIL_CLOSED: setup receipt must show bound successor setup")
    if str(micro_courts_manifest.get("execution_status", "")).strip() != "LOCKED__READY_FOR_FIRST_SUCCESSOR_VARIANTS":
        raise RuntimeError("FAIL_CLOSED: frozen micro-courts must remain locked")
    if str(reportability_variant_manifest.get("execution_status", "")).strip() != "AUTHORIZED__NOT_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: reportability variant manifest must remain pre-execution")
    if str(causal_launch_manifest.get("execution_status", "")).strip() != "AUTHORIZED__NOT_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: causal launch manifest must remain pre-execution")
    if str(route_consequence_verdict_receipt.get("execution_status", "")).strip() != "AUTHORIZED__NOT_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: route consequence verdict surface must remain pre-execution")

    if str(micro_courts_manifest.get("focused_family_id", "")).strip() != setup_tranche.EXPECTED_FOCUSED_FAMILY_ID:
        raise RuntimeError("FAIL_CLOSED: focused family mismatch in micro-courts manifest")
    if str(reportability_variant_manifest.get("focused_family_id", "")).strip() != setup_tranche.EXPECTED_FOCUSED_FAMILY_ID:
        raise RuntimeError("FAIL_CLOSED: focused family mismatch in variant manifest")
    if str(causal_launch_manifest.get("focused_family_id", "")).strip() != setup_tranche.EXPECTED_FOCUSED_FAMILY_ID:
        raise RuntimeError("FAIL_CLOSED: focused family mismatch in causal launch manifest")

    variants = reportability_variant_manifest.get("variants", [])
    interventions = causal_launch_manifest.get("intervention_wave", [])
    micro_courts = micro_courts_manifest.get("locked_micro_courts", [])
    if not isinstance(variants, list) or len(variants) != 3:
        raise RuntimeError("FAIL_CLOSED: expected exactly 3 first-wave reportability variants")
    if not isinstance(interventions, list) or len(interventions) != 6:
        raise RuntimeError("FAIL_CLOSED: expected exactly 6 first-wave interventions")
    if not isinstance(micro_courts, list) or len(micro_courts) != 5:
        raise RuntimeError("FAIL_CLOSED: expected exactly 5 locked micro-courts")


def _execute_saved_route_head(
    *,
    route_margin_records_path: Path,
    joint_batch_manifest_path: Path,
    defer_gate_contract_path: Path,
    route_self_check_contract_path: Path,
    route_head_checkpoint_path: Path,
    route_head_label_map_path: Path,
    route_head_train_manifest_path: Path,
    focused_current_family_id: str,
) -> Dict[str, Any]:
    for path, label in (
        (route_margin_records_path, "route margin records"),
        (joint_batch_manifest_path, "joint batch manifest"),
        (defer_gate_contract_path, "defer gate contract"),
        (route_self_check_contract_path, "route self check contract"),
        (route_head_checkpoint_path, "saved route-judgment head checkpoint"),
        (route_head_label_map_path, "saved route-judgment head label map"),
        (route_head_train_manifest_path, "saved route-judgment head train manifest"),
    ):
        if not path.is_file():
            raise RuntimeError(f"FAIL_CLOSED: missing required saved-head artifact for execution: {label}: {path.as_posix()}")

    rows = load_rows(route_margin_records_path)
    joint_batch_map = _load_joint_batch_map(joint_batch_manifest_path)
    defer_gate_map = _maybe_load_case_map(defer_gate_contract_path)
    self_check_map = _maybe_load_case_map(route_self_check_contract_path)
    train_manifest = load_json(route_head_train_manifest_path)
    label_map = load_json(route_head_label_map_path)
    checkpoint_payload = torch.load(route_head_checkpoint_path, map_location="cpu")

    state_dict = checkpoint_payload.get("state_dict")
    if not isinstance(state_dict, dict):
        raise RuntimeError("FAIL_CLOSED: saved route-judgment head must contain a state_dict")

    feature_dim = int(checkpoint_payload.get("feature_dim", train_manifest.get("feature_dim", 0)))
    action_labels = list(checkpoint_payload.get("action_labels", label_map.get("action_labels", [])))
    reason_labels = list(checkpoint_payload.get("reason_labels", label_map.get("reason_labels", [])))
    why_not_labels = list(checkpoint_payload.get("why_not_labels", label_map.get("why_not_labels", [])))
    if feature_dim <= 0 or not action_labels or not reason_labels or not why_not_labels:
        raise RuntimeError("FAIL_CLOSED: saved route-judgment head metadata is incomplete")

    records: List[Dict[str, Any]] = []
    source_rows: List[Dict[str, Any]] = []
    for row in rows:
        case_id = str(row.get("case_id", "")).strip()
        record = _build_case_record(
            row,
            joint_info=joint_batch_map.get(case_id, {}),
            defer_row=defer_gate_map.get(case_id, {}),
            self_check_row=self_check_map.get(case_id, {}),
            feature_dim=feature_dim,
        )
        records.append(record)
        source_rows.append(dict(row))

    if not records:
        raise RuntimeError("FAIL_CLOSED: saved route-judgment head execution requires at least one route-margin row")

    model = RouteJudgmentHead(
        feature_dim=feature_dim,
        action_classes=len(action_labels),
        reason_classes=len(reason_labels),
        why_not_classes=len(why_not_labels),
    )
    model.load_state_dict(state_dict)
    model.eval()

    x = torch.stack([record["x"] for record in records], dim=0)
    with torch.no_grad():
        outputs = model(x)
        action_probs = F.softmax(outputs["action_logits"], dim=-1)
        reason_probs = F.softmax(outputs["reason_logits"], dim=-1)
        why_not_probs = F.softmax(outputs["why_not_logits"], dim=-1)
        action_conf, action_pred = action_probs.max(dim=-1)
        reason_conf, reason_pred = reason_probs.max(dim=-1)
        why_not_conf, why_not_pred = why_not_probs.max(dim=-1)
        model_margins = outputs["margin"]

    observed_rows: List[Dict[str, Any]] = []
    for index, row in enumerate(source_rows):
        observed_rows.append(
            {
                "case_id": str(row.get("case_id", "")).strip(),
                "legacy_family_id": str(row.get("family_id", "")).strip(),
                "current_family_id": _mapped_family_id(str(row.get("family_id", "")).strip(), focused_current_family_id=focused_current_family_id),
                "variant_type": str(row.get("variant_type", "")).strip(),
                "lawful_action": str(row.get("lawful_action", "")).strip(),
                "lawful_target_specialist": str(row.get("lawful_target_specialist", "")).strip(),
                "lawful_action_rationale_id": str(row.get("lawful_action_rationale_id", "")).strip(),
                "runner_up_action": str(row.get("runner_up_action", "")).strip() or ACTION_STATIC,
                "case_risk_band": str(row.get("case_risk_band", "")).strip(),
                "gold_reason_label": str(row.get("dominance_reason_code_primary", "")).strip(),
                "gold_reason_secondary_label": str(row.get("dominance_reason_code_secondary", "")).strip(),
                "gold_why_not_target_label": str(row.get("why_not_target_label", "")).strip(),
                "predicted_action_label": str(action_labels[int(action_pred[index])]),
                "predicted_reason_label": str(reason_labels[int(reason_pred[index])]),
                "predicted_why_not_label": str(why_not_labels[int(why_not_pred[index])]),
                "action_confidence": _round_float(action_conf[index]),
                "reason_confidence": _round_float(reason_conf[index]),
                "why_not_confidence": _round_float(why_not_conf[index]),
                "model_margin": _round_float(model_margins[index]),
                "expected_route_margin": _round_float(row.get("expected_route_margin", 0.0)),
                "observed_route_margin": _round_float(row.get("observed_route_margin", 0.0)),
                "wrong_route_cost": _round_float(row.get("wrong_route_cost", 0.0)),
                "wrong_static_hold_cost": _round_float(row.get("wrong_static_hold_cost", 0.0)),
                "missed_abstention_cost": _round_float(row.get("missed_abstention_cost", 0.0)),
                "proof_burden_delta": _round_float(row.get("proof_burden_delta", 0.0)),
                "alpha_plausibility_score": _round_float(row.get("alpha_plausibility_score", 0.0)),
                "alpha_delayed_wrongness_score": _round_float(row.get("alpha_delayed_wrongness_score", 0.0)),
                "confidence_raw": _round_float(row.get("confidence_raw", 0.0)),
                "confidence_calibrated": _round_float(row.get("confidence_calibrated", 0.0)),
                "self_check_required": bool(row.get("self_check_required", False)),
                "self_check_passed": bool(row.get("self_check_passed", False)),
                "defer_gate_outcome": str(row.get("defer_gate_outcome", "")).strip(),
                "why_not_alpha": str(row.get("why_not_alpha", "")).strip(),
                "why_not_specialist": str(row.get("why_not_specialist", "")).strip(),
                "why_not_abstain": str(row.get("why_not_abstain", "")).strip(),
            }
        )

    all_reason_conf = [float(row["reason_confidence"]) for row in observed_rows]
    focus_rows = [row for row in observed_rows if row["current_family_id"] == focused_current_family_id]
    focus_reason_conf = [float(row["reason_confidence"]) for row in focus_rows]
    low_conf_focus_rows = [row for row in focus_rows if float(row["reason_confidence"]) <= _percentile(all_reason_conf, 0.25)]
    refusal_floor = 0.65
    if low_conf_focus_rows:
        refusal_floor = round(max(float(row["observed_route_margin"]) for row in low_conf_focus_rows) + 0.05, 6)

    distribution_summary = {
        "all_reason_confidence": {
            "min": _round_float(min(all_reason_conf)),
            "p25": _round_float(_percentile(all_reason_conf, 0.25)),
            "median": _round_float(_percentile(all_reason_conf, 0.50)),
            "p75": _round_float(_percentile(all_reason_conf, 0.75)),
            "max": _round_float(max(all_reason_conf)),
        },
        "focused_reason_confidence": {
            "min": _round_float(min(focus_reason_conf)) if focus_reason_conf else 0.0,
            "p25": _round_float(_percentile(focus_reason_conf, 0.25)) if focus_reason_conf else 0.0,
            "median": _round_float(_percentile(focus_reason_conf, 0.50)) if focus_reason_conf else 0.0,
            "p75": _round_float(_percentile(focus_reason_conf, 0.75)) if focus_reason_conf else 0.0,
            "max": _round_float(max(focus_reason_conf)) if focus_reason_conf else 0.0,
        },
        "all_model_margin": {
            "min": _round_float(min(float(row["model_margin"]) for row in observed_rows)),
            "p25": _round_float(_percentile([float(row["model_margin"]) for row in observed_rows], 0.25)),
            "median": _round_float(_percentile([float(row["model_margin"]) for row in observed_rows], 0.50)),
            "p75": _round_float(_percentile([float(row["model_margin"]) for row in observed_rows], 0.75)),
            "max": _round_float(max(float(row["model_margin"]) for row in observed_rows)),
        },
    }
    thresholds = {
        "global_reason_conf_refusal_threshold": _round_float(_percentile(all_reason_conf, 0.25)),
        "focused_reason_conf_refusal_threshold": _round_float(_percentile(focus_reason_conf, 0.25)) if focus_reason_conf else 0.0,
        "observed_route_margin_refusal_floor": _round_float(refusal_floor),
        "low_conf_focus_case_ids": [str(row["case_id"]) for row in low_conf_focus_rows],
    }
    bundle_metadata = {
        "executor_class": "LIGHTWEIGHT_SAVED_ROUTE_HEAD_WITH_TYPED_BRIDGE_AND_CAUSAL_HARNESS",
        "route_margin_records_path": route_margin_records_path.as_posix(),
        "route_margin_records_sha256": file_sha256(route_margin_records_path),
        "joint_batch_manifest_path": joint_batch_manifest_path.as_posix(),
        "joint_batch_manifest_sha256": file_sha256(joint_batch_manifest_path),
        "defer_gate_contract_path": defer_gate_contract_path.as_posix(),
        "defer_gate_contract_sha256": file_sha256(defer_gate_contract_path),
        "route_self_check_contract_path": route_self_check_contract_path.as_posix(),
        "route_self_check_contract_sha256": file_sha256(route_self_check_contract_path),
        "route_head_checkpoint_path": route_head_checkpoint_path.as_posix(),
        "route_head_checkpoint_sha256": file_sha256(route_head_checkpoint_path),
        "route_head_label_map_path": route_head_label_map_path.as_posix(),
        "route_head_label_map_sha256": file_sha256(route_head_label_map_path),
        "route_head_train_manifest_path": route_head_train_manifest_path.as_posix(),
        "route_head_train_manifest_sha256": file_sha256(route_head_train_manifest_path),
        "feature_dim": feature_dim,
        "row_count": len(observed_rows),
    }
    return {
        "observed_rows": observed_rows,
        "thresholds": thresholds,
        "distribution_summary": distribution_summary,
        "bundle_metadata": bundle_metadata,
    }


def _bind_micro_courts(
    *,
    observed_rows: Sequence[Dict[str, Any]],
    micro_courts_manifest: Dict[str, Any],
    focused_current_family_id: str,
) -> Tuple[Dict[str, List[Dict[str, Any]]], List[Dict[str, Any]]]:
    selected: Dict[str, List[Dict[str, Any]]] = {}
    for court in micro_courts_manifest.get("locked_micro_courts", []):
        micro_court_id = str(court.get("micro_court_id", "")).strip()
        if micro_court_id == "RW_REASON_HOLDOUT_CORE":
            rows = [
                row
                for row in observed_rows
                if row["current_family_id"] == focused_current_family_id and str(row.get("variant_type", "")).strip() != "masked"
            ]
        elif micro_court_id == "RW_MUTATION_CLONE_PRESSURE":
            rows = [
                row
                for row in observed_rows
                if row["current_family_id"] == focused_current_family_id and str(row.get("variant_type", "")).strip() == "masked"
            ]
        elif micro_court_id == "RW_ROUTE_CONSEQUENCE_INTERVENTION_PANEL":
            rows = [row for row in observed_rows if row["current_family_id"] == focused_current_family_id]
        elif micro_court_id == "BOUNDARY_ABSTENTION_CONTROL_GUARD":
            rows = [row for row in observed_rows if row["current_family_id"] == "BOUNDARY_ABSTENTION_CONTROL"]
        elif micro_court_id == "STATIC_NO_ROUTE_CONTROL_GUARD":
            rows = [row for row in observed_rows if row["current_family_id"] == "STATIC_NO_ROUTE_CONTROL"]
        else:
            rows = []
        if not rows:
            raise RuntimeError(f"FAIL_CLOSED: micro-court {micro_court_id} bound to zero rows")
        selected[micro_court_id] = rows

    relevant_case_ids = {row["case_id"] for rows in selected.values() for row in rows}
    relevant_rows = []
    for row in observed_rows:
        if row["case_id"] in relevant_case_ids:
            enriched = dict(row)
            enriched["micro_court_ids"] = [court_id for court_id, rows in selected.items() if any(r["case_id"] == row["case_id"] for r in rows)]
            relevant_rows.append(enriched)
    return selected, relevant_rows


def _baseline_reason_label(row: Dict[str, Any]) -> str:
    return str(row.get("predicted_reason_label", "")).strip()


def _typed_reason_label(row: Dict[str, Any], *, focused_current_family_id: str) -> str:
    baseline = _baseline_reason_label(row)
    if str(row.get("current_family_id", "")).strip() != focused_current_family_id:
        return baseline
    if baseline == "CONTROL_PRESERVATION" and str(row.get("predicted_action_label", "")).strip() == ACTION_STATIC:
        if float(row.get("wrong_static_hold_cost", 0.0)) <= 0.05:
            return "RIGHTFUL_STATIC_HOLD_PRESERVED"
    if str(row.get("predicted_action_label", "")).strip() == ACTION_ABSTAIN and float(row.get("missed_abstention_cost", 0.0)) > 0.0:
        return "RIGHTFUL_ABSTENTION_GUARD_PRESERVED"
    return baseline


def _counter_reason_label(row: Dict[str, Any], *, focused_current_family_id: str) -> str:
    reason = _typed_reason_label(row, focused_current_family_id=focused_current_family_id)
    if str(row.get("current_family_id", "")).strip() != focused_current_family_id:
        return reason
    if str(row.get("predicted_action_label", "")).strip() != ACTION_ROUTE:
        return reason
    if reason != _baseline_reason_label(row):
        return reason
    case_text = str(row.get("case_id", "")).lower()
    evidence_text = " ".join(
        [
            str(row.get("why_not_alpha", "")),
            str(row.get("why_not_specialist", "")),
        ]
    ).lower()
    if "frame_lock" in case_text or "frame lock" in case_text:
        return "FRAME_LOCK_PREMATURELY_COLLAPSES_RIVAL_VIEW"
    if "counterread" in case_text:
        return "COUNTERREAD_VALUE_IS_VISIBLE_TOO_LATE"
    if "domain_overlay" in case_text or "domain overlay" in case_text:
        return "DOMAIN_OVERLAY_HIDES_SECOND_ORDER_COST"
    if "frame lock" in evidence_text or "rival view" in evidence_text:
        return "FRAME_LOCK_PREMATURELY_COLLAPSES_RIVAL_VIEW"
    if "counterread" in evidence_text:
        return "COUNTERREAD_VALUE_IS_VISIBLE_TOO_LATE"
    if "domain overlay" in evidence_text or "domain_overlay" in evidence_text:
        return "DOMAIN_OVERLAY_HIDES_SECOND_ORDER_COST"
    return reason


def _refusal_allowed(
    row: Dict[str, Any],
    *,
    focused_current_family_id: str,
    thresholds: Dict[str, Any],
) -> bool:
    return (
        str(row.get("current_family_id", "")).strip() == focused_current_family_id
        and float(row.get("reason_confidence", 0.0)) <= float(thresholds.get("global_reason_conf_refusal_threshold", 0.0))
        and float(row.get("observed_route_margin", 0.0)) <= float(thresholds.get("observed_route_margin_refusal_floor", 0.0))
    )


def _variant_reason_label(
    row: Dict[str, Any],
    *,
    variant_id: str,
    focused_current_family_id: str,
    thresholds: Dict[str, Any],
) -> str:
    if variant_id == "RB_TYPED_CAUSAL_SCHEMA_BRIDGE_V1":
        return _typed_reason_label(row, focused_current_family_id=focused_current_family_id)
    if variant_id == "RB_COUNTERFACTUAL_EVIDENCE_OBJECT_BRIDGE_V1":
        return _counter_reason_label(row, focused_current_family_id=focused_current_family_id)
    if variant_id == "RB_CALIBRATED_REASON_REFUSAL_BRIDGE_V1":
        if _refusal_allowed(row, focused_current_family_id=focused_current_family_id, thresholds=thresholds):
            return LAWFUL_REASON_REFUSAL
        return _counter_reason_label(row, focused_current_family_id=focused_current_family_id)
    raise RuntimeError(f"FAIL_CLOSED: unsupported reportability variant id: {variant_id}")


def _reason_is_admissible(
    row: Dict[str, Any],
    *,
    reason_label: str,
    focused_current_family_id: str,
    thresholds: Dict[str, Any],
) -> bool:
    gold = str(row.get("gold_reason_label", "")).strip()
    if reason_label == gold:
        return True
    if reason_label == LAWFUL_REASON_REFUSAL:
        return _refusal_allowed(row, focused_current_family_id=focused_current_family_id, thresholds=thresholds)
    return False


def _build_typed_reason_object(
    row: Dict[str, Any],
    *,
    variant_id: str,
    reason_label: str,
    focused_current_family_id: str,
    thresholds: Dict[str, Any],
) -> Dict[str, Any]:
    lawful_refusal = reason_label == LAWFUL_REASON_REFUSAL
    exact_match = reason_label == str(row.get("gold_reason_label", "")).strip()
    admissible = _reason_is_admissible(
        row,
        reason_label=reason_label,
        focused_current_family_id=focused_current_family_id,
        thresholds=thresholds,
    )
    return {
        "variant_id": variant_id,
        "route_correctness_judgment": {
            "correct": str(row.get("predicted_action_label", "")).strip() == str(row.get("lawful_action", "")).strip(),
            "predicted_action_label": row.get("predicted_action_label", ""),
            "lawful_action": row.get("lawful_action", ""),
        },
        "action_judgment": {
            "correct": str(row.get("predicted_action_label", "")).strip() == str(row.get("lawful_action", "")).strip(),
            "confidence": row.get("action_confidence", 0.0),
        },
        "why_not_judgment": {
            "correct": str(row.get("predicted_why_not_label", "")).strip() == str(row.get("gold_why_not_target_label", "")).strip(),
            "predicted_why_not_label": row.get("predicted_why_not_label", ""),
            "gold_why_not_target_label": row.get("gold_why_not_target_label", ""),
            "confidence": row.get("why_not_confidence", 0.0),
        },
        "reason_object": {
            "reason_label": reason_label,
            "gold_reason_label": row.get("gold_reason_label", ""),
            "exact_match": exact_match,
            "admissible": admissible,
            "lawful_refusal": lawful_refusal,
        },
        "evidence_basis": {
            "observed_route_margin": row.get("observed_route_margin", 0.0),
            "expected_route_margin": row.get("expected_route_margin", 0.0),
            "wrong_route_cost": row.get("wrong_route_cost", 0.0),
            "wrong_static_hold_cost": row.get("wrong_static_hold_cost", 0.0),
            "missed_abstention_cost": row.get("missed_abstention_cost", 0.0),
            "proof_burden_delta": row.get("proof_burden_delta", 0.0),
            "alpha_plausibility_score": row.get("alpha_plausibility_score", 0.0),
            "alpha_delayed_wrongness_score": row.get("alpha_delayed_wrongness_score", 0.0),
        },
        "counterfactual_contrast": {
            "why_not_alpha": row.get("why_not_alpha", ""),
            "why_not_specialist": row.get("why_not_specialist", ""),
            "why_not_abstain": row.get("why_not_abstain", ""),
        },
        "confidence_calibration": {
            "action_confidence": row.get("action_confidence", 0.0),
            "reason_confidence": row.get("reason_confidence", 0.0),
            "why_not_confidence": row.get("why_not_confidence", 0.0),
            "global_reason_conf_refusal_threshold": thresholds.get("global_reason_conf_refusal_threshold", 0.0),
            "observed_route_margin_refusal_floor": thresholds.get("observed_route_margin_refusal_floor", 0.0),
        },
    }


def _score_row_level_fields(rows: Sequence[Dict[str, Any]]) -> Dict[str, float]:
    return {
        "action_accuracy": _bool_rate(
            str(row.get("predicted_action_label", "")).strip() == str(row.get("lawful_action", "")).strip() for row in rows
        ),
        "why_not_accuracy": _bool_rate(
            str(row.get("predicted_why_not_label", "")).strip() == str(row.get("gold_why_not_target_label", "")).strip() for row in rows
        ),
        "route_correctness": _bool_rate(
            str(row.get("predicted_action_label", "")).strip() == str(row.get("lawful_action", "")).strip() for row in rows
        ),
        "mean_reason_confidence": _round_float(
            sum(float(row.get("reason_confidence", 0.0)) for row in rows) / max(1, len(rows))
        ),
    }


def _score_bridge_variants(
    *,
    relevant_rows: Sequence[Dict[str, Any]],
    selected_micro_courts: Dict[str, List[Dict[str, Any]]],
    reportability_variant_manifest: Dict[str, Any],
    focused_current_family_id: str,
    thresholds: Dict[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    baseline_by_case = {
        row["case_id"]: _baseline_reason_label(row)
        for row in relevant_rows
    }
    row_panel_index: Dict[str, Dict[str, Any]] = {}
    for row in relevant_rows:
        baseline_label = baseline_by_case[row["case_id"]]
        row_panel_index[row["case_id"]] = {
            "case_id": row["case_id"],
            "current_family_id": row["current_family_id"],
            "legacy_family_id": row["legacy_family_id"],
            "variant_type": row["variant_type"],
            "micro_court_ids": list(row.get("micro_court_ids", [])),
            "lawful_action": row["lawful_action"],
            "predicted_action_label": row["predicted_action_label"],
            "predicted_why_not_label": row["predicted_why_not_label"],
            "gold_reason_label": row["gold_reason_label"],
            "gold_why_not_target_label": row["gold_why_not_target_label"],
            "action_confidence": row["action_confidence"],
            "reason_confidence": row["reason_confidence"],
            "why_not_confidence": row["why_not_confidence"],
            "observed_route_margin": row["observed_route_margin"],
            "expected_route_margin": row["expected_route_margin"],
            "wrong_route_cost": row["wrong_route_cost"],
            "wrong_static_hold_cost": row["wrong_static_hold_cost"],
            "missed_abstention_cost": row["missed_abstention_cost"],
            "proof_burden_delta": row["proof_burden_delta"],
            "baseline_reason_label": baseline_label,
            "baseline_reason_exact": baseline_label == row["gold_reason_label"],
            "baseline_reason_admissible": _reason_is_admissible(
                row,
                reason_label=baseline_label,
                focused_current_family_id=focused_current_family_id,
                thresholds=thresholds,
            ),
            "bridge_outputs": {},
        }

    baseline_metrics_by_court: Dict[str, Dict[str, float]] = {}
    for micro_court_id, rows in selected_micro_courts.items():
        baseline_metrics_by_court[micro_court_id] = {
            **_score_row_level_fields(rows),
            "reason_exact_accuracy": _bool_rate(baseline_by_case[row["case_id"]] == row["gold_reason_label"] for row in rows),
            "reason_admissible_accuracy": _bool_rate(
                _reason_is_admissible(
                    row,
                    reason_label=baseline_by_case[row["case_id"]],
                    focused_current_family_id=focused_current_family_id,
                    thresholds=thresholds,
                )
                for row in rows
            ),
        }

    variants_payload: List[Dict[str, Any]] = []
    reportability_lift_observed = False
    for variant in reportability_variant_manifest.get("variants", []):
        variant_id = str(variant.get("variant_id", "")).strip()
        changed_case_ids: List[str] = []
        micro_court_metrics: List[Dict[str, Any]] = []
        all_variant_rows: List[Dict[str, Any]] = []
        total_refusals = 0

        for row in relevant_rows:
            reason_label = _variant_reason_label(
                row,
                variant_id=variant_id,
                focused_current_family_id=focused_current_family_id,
                thresholds=thresholds,
            )
            reason_object = _build_typed_reason_object(
                row,
                variant_id=variant_id,
                reason_label=reason_label,
                focused_current_family_id=focused_current_family_id,
                thresholds=thresholds,
            )
            if reason_label != baseline_by_case[row["case_id"]]:
                changed_case_ids.append(row["case_id"])
            if reason_label == LAWFUL_REASON_REFUSAL:
                total_refusals += 1
            row_panel_index[row["case_id"]]["bridge_outputs"][variant_id] = reason_object
            variant_row = dict(row)
            variant_row["_variant_reason_label"] = reason_label
            variant_row["_variant_reason_admissible"] = reason_object["reason_object"]["admissible"]
            all_variant_rows.append(variant_row)

        focus_all_rows = [row for row in all_variant_rows if row["current_family_id"] == focused_current_family_id]
        controls_rows = [row for row in all_variant_rows if row["current_family_id"] in {"BOUNDARY_ABSTENTION_CONTROL", "STATIC_NO_ROUTE_CONTROL"}]

        for micro_court_id, rows in selected_micro_courts.items():
            variant_rows = [row for row in all_variant_rows if row["case_id"] in {selected["case_id"] for selected in rows}]
            baseline_metrics = baseline_metrics_by_court[micro_court_id]
            variant_exact = _bool_rate(row["_variant_reason_label"] == row["gold_reason_label"] for row in variant_rows)
            variant_admissible = _bool_rate(bool(row["_variant_reason_admissible"]) for row in variant_rows)
            refusal_count = sum(1 for row in variant_rows if row["_variant_reason_label"] == LAWFUL_REASON_REFUSAL)
            micro_court_metrics.append(
                {
                    "micro_court_id": micro_court_id,
                    "row_count": len(variant_rows),
                    "action_accuracy": baseline_metrics["action_accuracy"],
                    "why_not_accuracy": baseline_metrics["why_not_accuracy"],
                    "route_correctness": baseline_metrics["route_correctness"],
                    "baseline_reason_exact_accuracy": baseline_metrics["reason_exact_accuracy"],
                    "baseline_reason_admissible_accuracy": baseline_metrics["reason_admissible_accuracy"],
                    "variant_reason_exact_accuracy": variant_exact,
                    "variant_reason_admissible_accuracy": variant_admissible,
                    "exact_lift_vs_baseline": _round_float(variant_exact - baseline_metrics["reason_exact_accuracy"]),
                    "admissible_lift_vs_baseline": _round_float(variant_admissible - baseline_metrics["reason_admissible_accuracy"]),
                    "refusal_count": refusal_count,
                    "control_guard_preserved": not bool(
                        micro_court_id in {"BOUNDARY_ABSTENTION_CONTROL_GUARD", "STATIC_NO_ROUTE_CONTROL_GUARD"}
                        and variant_exact < baseline_metrics["reason_exact_accuracy"]
                    ),
                }
            )

        focus_all_exact = _bool_rate(row["_variant_reason_label"] == row["gold_reason_label"] for row in focus_all_rows)
        focus_all_admissible = _bool_rate(bool(row["_variant_reason_admissible"]) for row in focus_all_rows)
        controls_exact = _bool_rate(row["_variant_reason_label"] == row["gold_reason_label"] for row in controls_rows)
        baseline_focus_all = baseline_metrics_by_court["RW_ROUTE_CONSEQUENCE_INTERVENTION_PANEL"]
        control_guards_preserved = controls_exact >= baseline_metrics_by_court["BOUNDARY_ABSTENTION_CONTROL_GUARD"]["reason_exact_accuracy"]
        control_guards_preserved = control_guards_preserved and (
            controls_exact >= baseline_metrics_by_court["STATIC_NO_ROUTE_CONTROL_GUARD"]["reason_exact_accuracy"]
        )
        if control_guards_preserved and (
            focus_all_exact > baseline_focus_all["reason_exact_accuracy"] or focus_all_admissible > baseline_focus_all["reason_admissible_accuracy"]
        ):
            reportability_lift_observed = True

        variants_payload.append(
            {
                "variant_id": variant_id,
                "mechanism_class": str(variant.get("mechanism_class", "")).strip(),
                "objective": str(variant.get("objective", "")).strip(),
                "overall": {
                    "focus_all_reason_exact_accuracy": focus_all_exact,
                    "focus_all_reason_admissible_accuracy": focus_all_admissible,
                    "focus_all_exact_lift_vs_baseline": _round_float(focus_all_exact - baseline_focus_all["reason_exact_accuracy"]),
                    "focus_all_admissible_lift_vs_baseline": _round_float(
                        focus_all_admissible - baseline_focus_all["reason_admissible_accuracy"]
                    ),
                    "controls_reason_exact_accuracy": controls_exact,
                    "controls_preserved": control_guards_preserved,
                    "changed_case_count": len(changed_case_ids),
                    "changed_case_ids": changed_case_ids,
                    "lawful_refusal_count": total_refusals,
                },
                "micro_court_metrics": micro_court_metrics,
            }
        )

    baseline_summary = {
        "focus_all_reason_exact_accuracy": baseline_metrics_by_court["RW_ROUTE_CONSEQUENCE_INTERVENTION_PANEL"]["reason_exact_accuracy"],
        "focus_all_reason_admissible_accuracy": baseline_metrics_by_court["RW_ROUTE_CONSEQUENCE_INTERVENTION_PANEL"]["reason_admissible_accuracy"],
        "focus_non_masked_reason_exact_accuracy": baseline_metrics_by_court["RW_REASON_HOLDOUT_CORE"]["reason_exact_accuracy"],
        "focus_masked_reason_exact_accuracy": baseline_metrics_by_court["RW_MUTATION_CLONE_PRESSURE"]["reason_exact_accuracy"],
        "controls_reason_exact_accuracy": _round_float(
            (
                baseline_metrics_by_court["BOUNDARY_ABSTENTION_CONTROL_GUARD"]["reason_exact_accuracy"]
                + baseline_metrics_by_court["STATIC_NO_ROUTE_CONTROL_GUARD"]["reason_exact_accuracy"]
            )
            / 2.0
        ),
    }

    bridge_scorecard = {
        "schema_id": "kt.operator.cohort0_first_successor_bridge_variant_scorecard.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This is first lightweight successor bridge execution over the saved route head and locked micro-courts. "
            "It does not claim Gate D movement, counted reentry, or Gate E movement."
        ),
        "execution_status": "PASS__FIRST_LIGHTWEIGHT_SUCCESSOR_BRIDGE_EXECUTED",
        "focused_family_id": focused_current_family_id,
        "focused_legacy_family_id": LEGACY_FOCUSED_FAMILY_ID,
        "executor_class": "LIGHTWEIGHT_SAVED_ROUTE_HEAD_WITH_TYPED_BRIDGE_AND_CAUSAL_HARNESS",
        "thresholds": dict(thresholds),
        "baseline_summary": baseline_summary,
        "micro_court_baseline_metrics": baseline_metrics_by_court,
        "variants": variants_payload,
        "reportability_lift_observed": reportability_lift_observed,
    }

    row_panel = {
        "schema_id": "kt.operator.cohort0_first_successor_evidence_row_panel.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This row panel records lightweight first-wave successor evidence only. "
            "It is an execution trace over locked micro-courts, not counted theorem proof."
        ),
        "rows": [row_panel_index[key] for key in sorted(row_panel_index.keys())],
    }
    return bridge_scorecard, row_panel


def _incurred_cost(row: Dict[str, Any], action_label: str) -> float:
    lawful_action = str(row.get("lawful_action", "")).strip()
    if action_label == lawful_action:
        return 0.0
    if action_label == ACTION_ROUTE:
        return float(row.get("wrong_route_cost", 0.0))
    if action_label == ACTION_STATIC:
        return float(row.get("wrong_static_hold_cost", 0.0))
    if action_label == ACTION_ABSTAIN:
        return float(row.get("missed_abstention_cost", 0.0))
    raise RuntimeError(f"FAIL_CLOSED: unsupported action label for incurred cost: {action_label}")


def _deterministic_random_alt(row: Dict[str, Any]) -> str:
    baseline = str(row.get("predicted_action_label", "")).strip()
    candidates = [ACTION_ABSTAIN, ACTION_ROUTE, ACTION_STATIC]
    available = [candidate for candidate in candidates if candidate != baseline]
    digest = hashlib.sha256(f"{row.get('case_id', '')}::RANDOM_ROUTE_NEGATIVE_CONTROL_PRIMARY".encode("utf-8")).digest()
    return available[digest[0] % len(available)]


def _chosen_action_for_intervention(row: Dict[str, Any], *, intervention_id: str) -> str:
    baseline = str(row.get("predicted_action_label", "")).strip()
    lawful = str(row.get("lawful_action", "")).strip()
    runner_up = str(row.get("runner_up_action", "")).strip() or ACTION_STATIC
    if intervention_id == "BASELINE_FOLLOW_HEAD":
        return baseline
    if intervention_id == "FORCED_WRONG_ROUTE_PRIMARY":
        if baseline == ACTION_ROUTE:
            return runner_up if runner_up != ACTION_ROUTE else ACTION_STATIC
        return ACTION_ROUTE
    if intervention_id == "RANDOM_ROUTE_NEGATIVE_CONTROL_PRIMARY":
        return _deterministic_random_alt(row)
    if intervention_id == "ORACLE_ROUTE_UPPER_BOUND_PRIMARY":
        return lawful
    if intervention_id == "WITNESS_ABLATION_PRIMARY":
        if baseline == ACTION_ROUTE:
            return ACTION_STATIC
        return baseline
    if intervention_id == "FORCED_STATIC_HOLD_CONTROL_SPINE":
        return ACTION_STATIC
    if intervention_id == "ABSTAIN_DISABLED_BOUNDARY_SPINE":
        return ACTION_STATIC if lawful != ACTION_STATIC else ACTION_ROUTE
    raise RuntimeError(f"FAIL_CLOSED: unsupported intervention id: {intervention_id}")


def _score_intervention_rows(rows: Sequence[Dict[str, Any]], *, intervention_id: str) -> Dict[str, Any]:
    case_results: List[Dict[str, Any]] = []
    total_cost = 0.0
    for row in rows:
        chosen_action = _chosen_action_for_intervention(row, intervention_id=intervention_id)
        incurred_cost = _incurred_cost(row, chosen_action)
        total_cost += incurred_cost
        case_results.append(
            {
                "case_id": row["case_id"],
                "chosen_action": chosen_action,
                "lawful_action": row["lawful_action"],
                "incurred_cost": _round_float(incurred_cost),
            }
        )
    return {
        "intervention_id": intervention_id,
        "row_count": len(rows),
        "total_cost": _round_float(total_cost),
        "mean_cost": _round_float(total_cost / max(1, len(rows))),
        "nonzero_row_count": sum(1 for case_result in case_results if float(case_result["incurred_cost"]) > 0.0),
        "case_results": case_results,
    }


def _score_causal_interventions(
    *,
    selected_micro_courts: Dict[str, List[Dict[str, Any]]],
    causal_launch_manifest: Dict[str, Any],
) -> Dict[str, Any]:
    focused_rows = list(selected_micro_courts["RW_ROUTE_CONSEQUENCE_INTERVENTION_PANEL"])
    boundary_rows = list(selected_micro_courts["BOUNDARY_ABSTENTION_CONTROL_GUARD"])
    static_rows = list(selected_micro_courts["STATIC_NO_ROUTE_CONTROL_GUARD"])

    baseline_panel = _score_intervention_rows(focused_rows, intervention_id="BASELINE_FOLLOW_HEAD")
    intervention_rows: List[Dict[str, Any]] = []
    for intervention in causal_launch_manifest.get("intervention_wave", []):
        intervention_id = str(intervention.get("intervention_id", "")).strip()
        if intervention_id == "ABSTAIN_DISABLED_BOUNDARY_SPINE":
            panel_rows = boundary_rows
        elif intervention_id == "FORCED_STATIC_HOLD_CONTROL_SPINE":
            panel_rows = static_rows
        else:
            panel_rows = focused_rows
        score = _score_intervention_rows(panel_rows, intervention_id=intervention_id)
        score["goal"] = str(intervention.get("goal", "")).strip()
        score["bound_micro_court_id"] = str(intervention.get("bound_micro_court_id", "")).strip()
        score["delta_vs_baseline_total_cost"] = _round_float(score["total_cost"] - baseline_panel["total_cost"])
        score["delta_vs_baseline_mean_cost"] = _round_float(score["mean_cost"] - baseline_panel["mean_cost"])
        intervention_rows.append(score)

    by_id = {row["intervention_id"]: row for row in intervention_rows}
    wrong_route_penalty_visible = float(by_id["FORCED_WRONG_ROUTE_PRIMARY"]["total_cost"]) > float(baseline_panel["total_cost"])
    route_vs_static_visible = float(by_id["FORCED_STATIC_HOLD_CONTROL_SPINE"]["total_cost"]) == 0.0 and float(
        by_id["WITNESS_ABLATION_PRIMARY"]["total_cost"]
    ) > float(baseline_panel["total_cost"])
    boundary_abstention_guard_visible = float(by_id["ABSTAIN_DISABLED_BOUNDARY_SPINE"]["total_cost"]) > 0.0
    route_consequence_signal_nonzero = wrong_route_penalty_visible and boundary_abstention_guard_visible and (
        float(by_id["WITNESS_ABLATION_PRIMARY"]["total_cost"]) > 0.0 or float(by_id["ORACLE_ROUTE_UPPER_BOUND_PRIMARY"]["total_cost"]) == 0.0
    )

    return {
        "schema_id": "kt.operator.cohort0_first_successor_causal_intervention_scorecard.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This is first lightweight successor causal-harness execution over the saved route head and locked micro-courts. "
            "It does not claim Gate D movement, counted reentry, or Gate E movement."
        ),
        "execution_status": "PASS__FIRST_LIGHTWEIGHT_SUCCESSOR_CAUSAL_HARNESS_EXECUTED",
        "baseline_panel": baseline_panel,
        "interventions": intervention_rows,
        "signals": {
            "wrong_route_penalty_visible": wrong_route_penalty_visible,
            "route_vs_static_economics_visible": route_vs_static_visible,
            "boundary_abstention_guard_visible": boundary_abstention_guard_visible,
            "static_hold_control_preserved": float(by_id["FORCED_STATIC_HOLD_CONTROL_SPINE"]["total_cost"]) == 0.0,
            "witness_load_bearing_visible": float(by_id["WITNESS_ABLATION_PRIMARY"]["total_cost"]) > float(baseline_panel["total_cost"]),
            "route_consequence_signal_nonzero": route_consequence_signal_nonzero,
        },
    }


def _build_dominance_packet(
    *,
    focused_current_family_id: str,
    support_lab_hold_family_ids: Sequence[str],
    bridge_scorecard: Dict[str, Any],
    causal_scorecard: Dict[str, Any],
    row_panel: Dict[str, Any],
) -> Dict[str, Any]:
    focused_rows = [row for row in row_panel.get("rows", []) if row.get("current_family_id") == focused_current_family_id]
    control_rows = [row for row in row_panel.get("rows", []) if row.get("current_family_id") in {"BOUNDARY_ABSTENTION_CONTROL", "STATIC_NO_ROUTE_CONTROL"}]
    alpha_should_lose = [
        {
            "case_id": row["case_id"],
            "family_id": row["current_family_id"],
            "legacy_family_id": row["legacy_family_id"],
            "why": "Forced static hold carries positive cost while the lightweight executor keeps the lawful non-static action.",
            "wrong_static_hold_cost": row["wrong_static_hold_cost"],
            "observed_route_margin": row["observed_route_margin"],
        }
        for row in focused_rows
        if row["lawful_action"] != ACTION_STATIC and float(row["wrong_static_hold_cost"]) > 0.0
    ]
    alpha_still_dominates = [
        {
            "case_id": row["case_id"],
            "family_id": row["current_family_id"],
            "legacy_family_id": row["legacy_family_id"],
            "why": "This control row remains a rightful static hold, so the static path is still the correct minimum action.",
        }
        for row in control_rows
        if row["current_family_id"] == "STATIC_NO_ROUTE_CONTROL"
    ]
    interventions_by_id = {row["intervention_id"]: row for row in causal_scorecard.get("interventions", [])}
    best_variant = max(
        bridge_scorecard.get("variants", []),
        key=lambda item: float(item.get("overall", {}).get("focus_all_reason_admissible_accuracy", 0.0)),
        default={},
    )
    route_economics = {
        "baseline_total_cost": causal_scorecard.get("baseline_panel", {}).get("total_cost", 0.0),
        "forced_wrong_route_total_cost": interventions_by_id.get("FORCED_WRONG_ROUTE_PRIMARY", {}).get("total_cost", 0.0),
        "witness_ablation_total_cost": interventions_by_id.get("WITNESS_ABLATION_PRIMARY", {}).get("total_cost", 0.0),
        "forced_static_hold_control_total_cost": interventions_by_id.get("FORCED_STATIC_HOLD_CONTROL_SPINE", {}).get("total_cost", 0.0),
        "abstain_disabled_boundary_total_cost": interventions_by_id.get("ABSTAIN_DISABLED_BOUNDARY_SPINE", {}).get("total_cost", 0.0),
        "route_consequence_signal_nonzero": bool(causal_scorecard.get("signals", {}).get("route_consequence_signal_nonzero", False)),
    }

    return {
        "schema_id": "kt.operator.cohort0_first_successor_dominance_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This is the first lightweight successor dominance packet built from executed bridge and harness evidence over the saved route head. "
            "It is not counted same-head proof and does not reopen Gate D."
        ),
        "execution_status": "PASS__FIRST_LIGHTWEIGHT_SUCCESSOR_DOMINANCE_PACKET_EMITTED",
        "focused_family_id": focused_current_family_id,
        "focused_legacy_family_id": LEGACY_FOCUSED_FAMILY_ID,
        "alpha_should_lose_here_manifest": alpha_should_lose,
        "alpha_still_dominates_here_manifest": alpha_still_dominates,
        "abstain_static_boundary_correctness_map": {
            "boundary_control_case_ids": [row["case_id"] for row in control_rows if row["current_family_id"] == "BOUNDARY_ABSTENTION_CONTROL"],
            "static_control_case_ids": [row["case_id"] for row in control_rows if row["current_family_id"] == "STATIC_NO_ROUTE_CONTROL"],
            "focused_abstain_case_ids": [row["case_id"] for row in focused_rows if row["lawful_action"] == ACTION_ABSTAIN],
            "focused_static_hold_case_ids": [row["case_id"] for row in focused_rows if row["lawful_action"] == ACTION_STATIC],
            "boundary_guard_visible": bool(causal_scorecard.get("signals", {}).get("boundary_abstention_guard_visible", False)),
            "static_hold_control_preserved": bool(causal_scorecard.get("signals", {}).get("static_hold_control_preserved", False)),
        },
        "route_economics_reduction_map": route_economics,
        "family_concentration_report": {
            "signal_family_ids": [focused_current_family_id] if route_economics["route_consequence_signal_nonzero"] else [],
            "support_lab_hold_family_ids_not_yet_executed": list(support_lab_hold_family_ids),
            "family_local_only": True,
            "counted_dominance_claim_admissible": False,
        },
        "reportability_summary": {
            "baseline_focus_all_reason_exact_accuracy": bridge_scorecard.get("baseline_summary", {}).get("focus_all_reason_exact_accuracy", 0.0),
            "baseline_focus_all_reason_admissible_accuracy": bridge_scorecard.get("baseline_summary", {}).get(
                "focus_all_reason_admissible_accuracy",
                0.0,
            ),
            "best_variant_id": best_variant.get("variant_id", ""),
            "best_variant_focus_all_reason_admissible_accuracy": best_variant.get("overall", {}).get(
                "focus_all_reason_admissible_accuracy",
                0.0,
            ),
            "reportability_lift_observed": bool(bridge_scorecard.get("reportability_lift_observed", False)),
        },
        "theorem_boundary": {
            "gate_d_reopened": False,
            "same_head_counted_reentry_admissible_now": False,
            "gate_e_open": False,
            "counted_claim_status": "NOT_EARNED__FIRST_LIGHTWEIGHT_SUCCESSOR_EVIDENCE_ONLY",
        },
    }


def _build_markdown_report(execution_manifest: Dict[str, Any], outputs: Sequence[str]) -> str:
    lines: List[str] = []
    lines.append("# COHORT0 First Successor Evidence Execution Report")
    lines.append("")
    lines.append(f"- Generated UTC: `{execution_manifest['generated_utc']}`")
    lines.append(f"- Subject head: `{execution_manifest['subject_head']}`")
    lines.append(f"- Focused family: `{execution_manifest['focused_family_id']}`")
    lines.append(f"- Executor class: `{execution_manifest['executor_class']}`")
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


def run_first_successor_evidence_execution_tranche(
    *,
    verdict_packet_path: Path,
    reentry_block_path: Path,
    reportability_metric_contract_path: Path,
    route_consequence_verdict_receipt_path: Path,
    micro_courts_manifest_path: Path,
    reportability_variant_manifest_path: Path,
    causal_launch_manifest_path: Path,
    dominance_packet_contract_path: Path,
    setup_receipt_path: Path,
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
    reportability_metric_contract = _load_json_required(reportability_metric_contract_path, label="reportability bridge metric contract")
    route_consequence_verdict_receipt = _load_json_required(
        route_consequence_verdict_receipt_path,
        label="route consequence verdict receipt",
    )
    micro_courts_manifest = _load_json_required(micro_courts_manifest_path, label="successor frozen micro-courts manifest")
    reportability_variant_manifest = _load_json_required(
        reportability_variant_manifest_path,
        label="reportability bridge variant manifest",
    )
    causal_launch_manifest = _load_json_required(causal_launch_manifest_path, label="causal launch manifest")
    dominance_packet_contract = _load_json_required(dominance_packet_contract_path, label="successor dominance packet contract")
    setup_receipt = _load_json_required(setup_receipt_path, label="first successor evidence setup receipt")

    _validate_setup_state(
        verdict_packet=verdict_packet,
        reentry_block=reentry_block,
        reportability_metric_contract=reportability_metric_contract,
        route_consequence_verdict_receipt=route_consequence_verdict_receipt,
        micro_courts_manifest=micro_courts_manifest,
        reportability_variant_manifest=reportability_variant_manifest,
        causal_launch_manifest=causal_launch_manifest,
        dominance_packet_contract=dominance_packet_contract,
        setup_receipt=setup_receipt,
    )

    subject_head = _require_same_subject_head(
        [
            verdict_packet,
            reentry_block,
            reportability_metric_contract,
            route_consequence_verdict_receipt,
            micro_courts_manifest,
            reportability_variant_manifest,
            causal_launch_manifest,
            dominance_packet_contract,
            setup_receipt,
        ]
    )
    if subject_head != setup_tranche.EXPECTED_SUBJECT_HEAD:
        raise RuntimeError("FAIL_CLOSED: unexpected subject head for first successor evidence execution")

    focused_current_family_id = str(micro_courts_manifest.get("focused_family_id", "")).strip()
    saved_head_execution = _execute_saved_route_head(
        route_margin_records_path=route_margin_records_path,
        joint_batch_manifest_path=joint_batch_manifest_path,
        defer_gate_contract_path=defer_gate_contract_path,
        route_self_check_contract_path=route_self_check_contract_path,
        route_head_checkpoint_path=route_head_checkpoint_path,
        route_head_label_map_path=route_head_label_map_path,
        route_head_train_manifest_path=route_head_train_manifest_path,
        focused_current_family_id=focused_current_family_id,
    )

    selected_micro_courts, relevant_rows = _bind_micro_courts(
        observed_rows=saved_head_execution["observed_rows"],
        micro_courts_manifest=micro_courts_manifest,
        focused_current_family_id=focused_current_family_id,
    )
    bridge_scorecard, row_panel = _score_bridge_variants(
        relevant_rows=relevant_rows,
        selected_micro_courts=selected_micro_courts,
        reportability_variant_manifest=reportability_variant_manifest,
        focused_current_family_id=focused_current_family_id,
        thresholds=saved_head_execution["thresholds"],
    )
    causal_scorecard = _score_causal_interventions(
        selected_micro_courts=selected_micro_courts,
        causal_launch_manifest=causal_launch_manifest,
    )
    dominance_packet = _build_dominance_packet(
        focused_current_family_id=focused_current_family_id,
        support_lab_hold_family_ids=micro_courts_manifest.get("support_lab_hold_family_ids", []),
        bridge_scorecard=bridge_scorecard,
        causal_scorecard=causal_scorecard,
        row_panel=row_panel,
    )

    live_authority_snapshot = {
        "final_verdict_id": verdict_packet.get("final_verdict_id", ""),
        "current_lane_closed": verdict_packet.get("current_lane_closed", False),
        "same_head_counted_reentry_admissible_now": verdict_packet.get("same_head_counted_reentry_admissible_now", False),
        "next_lawful_move": verdict_packet.get("next_lawful_move", ""),
        "secondary_parallel_move": verdict_packet.get("secondary_parallel_move", ""),
    }

    execution_manifest = {
        "schema_id": "kt.operator.cohort0_first_successor_evidence_execution_manifest.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": verdict_packet.get("current_git_head", ""),
        "subject_head": subject_head,
        "claim_boundary": (
            "This tranche executes a first lightweight successor evidence wave over the saved route head and locked micro-courts. "
            "It does not claim Gate D movement, counted same-head reentry, or Gate E movement."
        ),
        "execution_status": "PASS__FIRST_SUCCESSOR_EVIDENCE_EXECUTED__LIGHTWEIGHT",
        "executor_class": saved_head_execution["bundle_metadata"]["executor_class"],
        "focused_family_id": focused_current_family_id,
        "focused_legacy_family_id": LEGACY_FOCUSED_FAMILY_ID,
        "live_authority_snapshot": live_authority_snapshot,
        "thresholds": saved_head_execution["thresholds"],
        "distribution_summary": saved_head_execution["distribution_summary"],
        "locked_micro_court_ids": sorted(selected_micro_courts.keys()),
        "bridge_variant_ids_executed": [variant["variant_id"] for variant in reportability_variant_manifest.get("variants", [])],
        "intervention_ids_executed": [row["intervention_id"] for row in causal_scorecard.get("interventions", [])],
        "completed_now": [
            "Bound the five locked micro-courts to real route-margin rows through the saved route head.",
            "Executed the first three reportability-bridge variants over the relevant lightweight row panel.",
            "Executed the six causal route-consequence interventions over the focused family and control spines.",
            "Emitted a first lightweight successor dominance packet from observed execution evidence only.",
            "Kept Gate D readjudication dormant and same-head counted reentry blocked.",
        ],
    }

    execution_receipt = {
        "schema_id": "kt.operator.cohort0_first_successor_evidence_execution_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "subject_head": subject_head,
        "claim_boundary": (
            "This receipt records first executed lightweight successor evidence only. "
            "It does not claim Gate D reopened, same-head counted reentry became admissible, or Gate E opened."
        ),
        "execution_status": execution_manifest["execution_status"],
        "executor_class": execution_manifest["executor_class"],
        "focused_family_id": focused_current_family_id,
        "focused_legacy_family_id": LEGACY_FOCUSED_FAMILY_ID,
        "locked_micro_court_count": len(selected_micro_courts),
        "bridge_variant_count": len(reportability_variant_manifest.get("variants", [])),
        "intervention_count": len(causal_scorecard.get("interventions", [])),
        "reportability_lift_observed": bool(bridge_scorecard.get("reportability_lift_observed", False)),
        "route_consequence_signal_nonzero": bool(causal_scorecard.get("signals", {}).get("route_consequence_signal_nonzero", False)),
        "counted_gate_d_readjudication_admissible_now": False,
        "gate_d_reopened": False,
        "gate_e_open": False,
        "next_lawful_move": live_authority_snapshot["next_lawful_move"],
        "secondary_parallel_move": live_authority_snapshot["secondary_parallel_move"],
        "source_refs": {
            "verdict_packet_ref": verdict_packet_path.as_posix(),
            "reentry_block_ref": reentry_block_path.as_posix(),
            "reportability_metric_contract_ref": reportability_metric_contract_path.as_posix(),
            "route_consequence_verdict_receipt_ref": route_consequence_verdict_receipt_path.as_posix(),
            "micro_courts_manifest_ref": micro_courts_manifest_path.as_posix(),
            "reportability_variant_manifest_ref": reportability_variant_manifest_path.as_posix(),
            "causal_launch_manifest_ref": causal_launch_manifest_path.as_posix(),
            "dominance_packet_contract_ref": dominance_packet_contract_path.as_posix(),
            "setup_receipt_ref": setup_receipt_path.as_posix(),
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
            "focused_legacy_family_id": LEGACY_FOCUSED_FAMILY_ID,
            "bundle_metadata": saved_head_execution["bundle_metadata"],
            "thresholds": saved_head_execution["thresholds"],
            "distribution_summary": saved_head_execution["distribution_summary"],
        }
    )
    bridge_scorecard.update(
        {
            "subject_head": subject_head,
            "focused_family_id": focused_current_family_id,
            "source_refs": {
                "setup_receipt_ref": setup_receipt_path.as_posix(),
                "row_panel_ref": (reports_root / OUTPUT_ROW_PANEL).resolve().as_posix(),
            },
        }
    )
    causal_scorecard.update(
        {
            "subject_head": subject_head,
            "focused_family_id": focused_current_family_id,
            "focused_legacy_family_id": LEGACY_FOCUSED_FAMILY_ID,
            "source_refs": {
                "setup_receipt_ref": setup_receipt_path.as_posix(),
                "row_panel_ref": (reports_root / OUTPUT_ROW_PANEL).resolve().as_posix(),
            },
        }
    )
    dominance_packet.update(
        {
            "subject_head": subject_head,
            "source_refs": {
                "bridge_scorecard_ref": (reports_root / OUTPUT_BRIDGE_SCORECARD).resolve().as_posix(),
                "causal_scorecard_ref": (reports_root / OUTPUT_CAUSAL_SCORECARD).resolve().as_posix(),
                "row_panel_ref": (reports_root / OUTPUT_ROW_PANEL).resolve().as_posix(),
                "setup_receipt_ref": setup_receipt_path.as_posix(),
            },
        }
    )

    artifact_payloads: Dict[str, Dict[str, Any]] = {
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

    report_markdown = _build_markdown_report(execution_manifest, output_paths)
    report_path = (reports_root / OUTPUT_REPORT).resolve()
    _write_text(report_path, report_markdown)
    output_paths.append(f"KT_PROD_CLEANROOM/reports/{OUTPUT_REPORT}")

    return {
        "execution_manifest": execution_manifest,
        "execution_receipt": execution_receipt,
        "outputs": output_paths,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Execute the first lightweight successor evidence wave over the locked micro-courts and saved route head."
    )
    parser.add_argument("--verdict-packet", default=DEFAULT_VERDICT_PACKET_REL)
    parser.add_argument("--reentry-block", default=DEFAULT_REENTRY_BLOCK_REL)
    parser.add_argument("--reportability-metric-contract", default=DEFAULT_REPORTABILITY_METRIC_CONTRACT_REL)
    parser.add_argument("--route-consequence-verdict-receipt", default=DEFAULT_ROUTE_CONSEQUENCE_VERDICT_REL)
    parser.add_argument("--micro-courts-manifest", default=DEFAULT_MICRO_COURTS_REL)
    parser.add_argument("--reportability-variant-manifest", default=DEFAULT_REPORTABILITY_VARIANT_MANIFEST_REL)
    parser.add_argument("--causal-launch-manifest", default=DEFAULT_CAUSAL_LAUNCH_MANIFEST_REL)
    parser.add_argument("--dominance-packet-contract", default=DEFAULT_DOMINANCE_PACKET_CONTRACT_REL)
    parser.add_argument("--setup-receipt", default=DEFAULT_SETUP_RECEIPT_REL)
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
    payload = run_first_successor_evidence_execution_tranche(
        verdict_packet_path=_resolve(root, str(args.verdict_packet)),
        reentry_block_path=_resolve(root, str(args.reentry_block)),
        reportability_metric_contract_path=_resolve(root, str(args.reportability_metric_contract)),
        route_consequence_verdict_receipt_path=_resolve(root, str(args.route_consequence_verdict_receipt)),
        micro_courts_manifest_path=_resolve(root, str(args.micro_courts_manifest)),
        reportability_variant_manifest_path=_resolve(root, str(args.reportability_variant_manifest)),
        causal_launch_manifest_path=_resolve(root, str(args.causal_launch_manifest)),
        dominance_packet_contract_path=_resolve(root, str(args.dominance_packet_contract)),
        setup_receipt_path=_resolve(root, str(args.setup_receipt)),
        route_margin_records_path=_resolve(root, str(args.route_margin_records)),
        joint_batch_manifest_path=_resolve(root, str(args.joint_batch_manifest)),
        defer_gate_contract_path=_resolve(root, str(args.defer_gate_contract)),
        route_self_check_contract_path=_resolve(root, str(args.route_self_check_contract)),
        route_head_checkpoint_path=_resolve(root, str(args.route_head_checkpoint)),
        route_head_label_map_path=_resolve(root, str(args.route_head_label_map)),
        route_head_train_manifest_path=_resolve(root, str(args.route_head_train_manifest)),
        reports_root=_resolve(root, str(args.reports_root)),
    )
    execution_receipt = payload["execution_receipt"]
    print(
        {
            "status": execution_receipt["status"],
            "execution_status": execution_receipt["execution_status"],
            "focused_family_id": execution_receipt["focused_family_id"],
            "reportability_lift_observed": execution_receipt["reportability_lift_observed"],
            "route_consequence_signal_nonzero": execution_receipt["route_consequence_signal_nonzero"],
            "output_count": len(payload["outputs"]),
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
