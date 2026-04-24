from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_cross_lane_reentry_prep_screening_tranche as prep_screen
from tools.operator import cohort0_dual_lane_first_execution_tranche as dual_lane
from tools.operator import cohort0_dual_lane_successor_controller_tranche as controller
from tools.operator import cohort0_first_successor_evidence_setup_tranche as setup_tranche
from tools.operator import cohort0_gate_d_successor_execution_charter_tranche as successor_charter
from tools.operator import cohort0_lane_a_promoted_survivor_execution_tranche as lane_a_exec
from tools.operator import cohort0_lane_b_family_level_bridge_harness_tranche as lane_b_exec
from tools.operator import cohort0_lane_b_stage_pack_hydration_tranche as lane_b_hydration
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_VERDICT_PACKET_REL = setup_tranche.DEFAULT_VERDICT_PACKET_REL
DEFAULT_REENTRY_BLOCK_REL = setup_tranche.DEFAULT_REENTRY_BLOCK_REL
DEFAULT_SUCCESSOR_REENTRY_CONTRACT_REL = (
    f"KT_PROD_CLEANROOM/reports/{successor_charter.OUTPUT_SUCCESSOR_REENTRY_CONTRACT}"
)
DEFAULT_SUCCESSOR_READJUDICATION_MANIFEST_REL = (
    f"KT_PROD_CLEANROOM/reports/{successor_charter.OUTPUT_READJUDICATION_MANIFEST}"
)
DEFAULT_LANE_A_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{lane_a_exec.OUTPUT_RECEIPT}"
DEFAULT_LANE_A_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{lane_a_exec.OUTPUT_SCORECARD}"
DEFAULT_LANE_B_HYDRATION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{lane_b_hydration.OUTPUT_HYDRATION_RECEIPT}"
DEFAULT_LANE_B_HYDRATED_CASE_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{lane_b_hydration.OUTPUT_HYDRATED_CASE_PACKET}"
DEFAULT_LANE_B_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{lane_b_exec.OUTPUT_RECEIPT}"
DEFAULT_LANE_B_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{lane_b_exec.OUTPUT_SCORECARD}"
DEFAULT_CROSS_LANE_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{lane_b_exec.OUTPUT_COMPARATIVE_PACKET}"
DEFAULT_SCREENING_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{prep_screen.OUTPUT_SCREENING_PACKET}"
DEFAULT_SCREENING_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{prep_screen.OUTPUT_RECEIPT}"
DEFAULT_LANE_A_RESERVE_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{prep_screen.OUTPUT_LANE_A_RESERVE_SCORECARD}"
DEFAULT_LANE_B_RESERVE_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{prep_screen.OUTPUT_LANE_B_RESERVE_SCORECARD}"
DEFAULT_PROMOTION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{controller.OUTPUT_DUAL_LANE_PROMOTION_RECEIPT}"
DEFAULT_REJECTION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{controller.OUTPUT_DUAL_LANE_REJECTION_RECEIPT}"
DEFAULT_REPORTS_ROOT_REL = setup_tranche.DEFAULT_REPORTS_ROOT_REL

OUTPUT_PACKET = "cohort0_successor_reentry_prep_packet.json"
OUTPUT_RECEIPT = "cohort0_successor_reentry_prep_receipt.json"
OUTPUT_REPORT = "COHORT0_SUCCESSOR_REENTRY_PREP_REPORT.md"

NEXT_LAWFUL_MOVE = "EXECUTE_SUCCESSOR_GATE_D_REENTRY_ADMISSIBILITY_SCREEN__POST_PREP_PACKET"


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
        raise RuntimeError("FAIL_CLOSED: successor reentry-prep packet requires one same-head authority line")
    return next(iter(heads))


def _round_float(value: Any, digits: int = 6) -> float:
    return round(float(value), digits)


def _index_by_key(rows: Sequence[Dict[str, Any]], key: str) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        row_key = str(row.get(key, "")).strip()
        if row_key:
            out[row_key] = row
    return out


def _promoted_items(receipt: Dict[str, Any], *, lane: str) -> List[str]:
    return [
        str(item.get("item_id", "")).strip()
        for item in receipt.get("promotions", [])
        if isinstance(item, dict) and str(item.get("lane", "")).strip() == lane and str(item.get("item_id", "")).strip()
    ]


def _rejected_items(receipt: Dict[str, Any], *, lane: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for item in receipt.get("rejections", []):
        if not isinstance(item, dict):
            continue
        if str(item.get("lane", "")).strip() != lane:
            continue
        item_id = str(item.get("item_id", "")).strip()
        disposition = str(item.get("disposition", "")).strip()
        if item_id:
            out.append({"item_id": item_id, "disposition": disposition})
    return out


def _validate_inputs(
    *,
    verdict_packet: Dict[str, Any],
    reentry_block: Dict[str, Any],
    successor_reentry_contract: Dict[str, Any],
    successor_readjudication_manifest: Dict[str, Any],
    lane_a_receipt: Dict[str, Any],
    lane_a_scorecard: Dict[str, Any],
    lane_b_hydration_receipt: Dict[str, Any],
    lane_b_hydrated_case_packet: Dict[str, Any],
    lane_b_receipt: Dict[str, Any],
    lane_b_scorecard: Dict[str, Any],
    cross_lane_packet: Dict[str, Any],
    screening_packet: Dict[str, Any],
    screening_receipt: Dict[str, Any],
    lane_a_reserve_scorecard: Dict[str, Any],
    lane_b_reserve_scorecard: Dict[str, Any],
    promotion_receipt: Dict[str, Any],
    rejection_receipt: Dict[str, Any],
) -> None:
    for payload, label in (
        (verdict_packet, "hardened ceiling verdict packet"),
        (reentry_block, "gate d reentry block contract"),
        (successor_reentry_contract, "successor gate d reentry contract"),
        (successor_readjudication_manifest, "successor gate d readjudication manifest"),
        (lane_a_receipt, "lane a promoted-survivor receipt"),
        (lane_a_scorecard, "lane a promoted-survivor scorecard"),
        (lane_b_hydration_receipt, "lane b hydration receipt"),
        (lane_b_hydrated_case_packet, "lane b hydrated case packet"),
        (lane_b_receipt, "lane b family-level receipt"),
        (lane_b_scorecard, "lane b family-level scorecard"),
        (cross_lane_packet, "cross-lane comparative packet"),
        (screening_packet, "cross-lane reentry-prep screening packet"),
        (screening_receipt, "cross-lane reentry-prep screening receipt"),
        (lane_a_reserve_scorecard, "lane a reserve challenge scorecard"),
        (lane_b_reserve_scorecard, "lane b reserve challenge scorecard"),
        (promotion_receipt, "dual-lane promotion receipt"),
        (rejection_receipt, "dual-lane rejection receipt"),
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

    if str(successor_reentry_contract.get("execution_status", "")).strip() != "AUTHORIZED__NOT_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: successor reentry contract must remain authorized-only")
    if str(successor_readjudication_manifest.get("execution_status", "")).strip() != "AUTHORIZED__NOT_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: successor readjudication manifest must remain authorized-only")

    if str(screening_receipt.get("execution_status", "")).strip() != "PASS__CROSS_LANE_REENTRY_PREP_SCREEN_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: cross-lane reentry-prep screening must exist")
    if not bool(screening_receipt.get("successor_reentry_prep_packet_authorized", False)):
        raise RuntimeError("FAIL_CLOSED: successor reentry-prep packet must be authorized before authoring")
    if str(screening_receipt.get("next_lawful_move", "")).strip() != "AUTHOR_SUCCESSOR_REENTRY_PREP_PACKET__STRICTLY_PRE_GATE_D":
        raise RuntimeError("FAIL_CLOSED: reentry-prep screen next move mismatch")

    if str(lane_a_receipt.get("execution_status", "")).strip() != "PASS__LANE_A_PROMOTED_SURVIVOR_FULL_EXECUTION":
        raise RuntimeError("FAIL_CLOSED: Lane A promoted-survivor execution must exist")
    if str(lane_b_hydration_receipt.get("execution_status", "")).strip() != "PASS__LANE_B_STAGE_PACK_HYDRATION_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: Lane B hydration must exist")
    if str(lane_b_receipt.get("execution_status", "")).strip() != "PASS__LANE_B_FAMILY_LEVEL_BRIDGE_HARNESS_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: Lane B family-level execution must exist")
    if str(cross_lane_packet.get("execution_status", "")).strip() != "PASS__CROSS_LANE_COMPARATIVE_PACKET_EMITTED":
        raise RuntimeError("FAIL_CLOSED: cross-lane comparative packet must exist")

    for receipt in (lane_a_receipt, lane_b_hydration_receipt, lane_b_receipt, screening_receipt):
        if bool(receipt.get("same_head_counted_reentry_admissible_now", True)):
            raise RuntimeError("FAIL_CLOSED: counted reentry must remain blocked entering successor reentry-prep")
        if bool(receipt.get("gate_d_reopened", True)):
            raise RuntimeError("FAIL_CLOSED: Gate D must remain closed entering successor reentry-prep")
        if bool(receipt.get("gate_e_open", True)):
            raise RuntimeError("FAIL_CLOSED: Gate E must remain closed entering successor reentry-prep")

    comparative_read = dict(cross_lane_packet.get("comparative_read", {}))
    if not bool(comparative_read.get("lane_a_remains_numeric_benchmark_witness", False)):
        raise RuntimeError("FAIL_CLOSED: Lane A benchmark witness status must remain true")
    if not bool(comparative_read.get("lane_b_now_executed_on_materially_distinct_family_surface", False)):
        raise RuntimeError("FAIL_CLOSED: Lane B materially distinct execution must remain true")
    if not bool(comparative_read.get("dominance_surface_broadening_visible", False)):
        raise RuntimeError("FAIL_CLOSED: dominance broadening must be visible before prep packet authoring")


def _build_packet(
    *,
    subject_head: str,
    lane_a_scorecard: Dict[str, Any],
    lane_b_hydration_receipt: Dict[str, Any],
    lane_b_hydrated_case_packet: Dict[str, Any],
    lane_b_scorecard: Dict[str, Any],
    cross_lane_packet: Dict[str, Any],
    screening_packet: Dict[str, Any],
    screening_receipt: Dict[str, Any],
    lane_a_reserve_scorecard: Dict[str, Any],
    lane_b_reserve_scorecard: Dict[str, Any],
    promotion_receipt: Dict[str, Any],
    rejection_receipt: Dict[str, Any],
    source_refs: Dict[str, str],
) -> Dict[str, Any]:
    lane_a_full_metrics = dict(lane_a_scorecard.get("full_panel_metrics", {}))
    lane_b_overall_metrics = dict(lane_b_scorecard.get("overall_metrics", {}))
    lane_b_family_metrics = list(lane_b_scorecard.get("family_metrics", []))
    comparative_read = dict(cross_lane_packet.get("comparative_read", {}))
    hydrated_families = list(lane_b_hydrated_case_packet.get("hydrated_families", []))

    lane_a_promoted_ids = _promoted_items(
        promotion_receipt,
        lane="lane_a_mutation_generation_assault",
    )
    lane_b_promoted_ids = _promoted_items(
        promotion_receipt,
        lane="lane_b_new_route_bearing_family_discovery",
    )
    lane_b_rejections = _rejected_items(
        rejection_receipt,
        lane="lane_b_new_route_bearing_family_discovery",
    )

    lane_a_lifts = {
        "bridge_exact_lift": _round_float(
            float(lane_a_full_metrics.get("selected_bridge_reason_exact_accuracy", 0.0))
            - float(lane_a_full_metrics.get("baseline_reason_exact_accuracy", 0.0))
        ),
        "bridge_admissible_lift": _round_float(
            float(lane_a_full_metrics.get("selected_bridge_reason_admissible_accuracy", 0.0))
            - float(lane_a_full_metrics.get("baseline_reason_admissible_accuracy", 0.0))
        ),
    }

    lane_b_family_summary = [
        {
            "family_id": str(item.get("family_id", "")).strip(),
            "all_case_exact_accuracy": item.get("all_case_metrics", {}).get("bridge_reason_exact_accuracy", 0.0),
            "all_case_admissible_accuracy": item.get("all_case_metrics", {}).get("bridge_reason_admissible_accuracy", 0.0),
            "route_consequence_visible_rate": item.get("all_case_metrics", {}).get("route_consequence_visible_rate", 0.0),
            "visible_case_count": item.get("visible_case_metrics", {}).get("row_count", 0),
            "held_out_case_count": item.get("held_out_case_metrics", {}).get("row_count", 0),
        }
        for item in lane_b_family_metrics
    ]

    reserve_challenge_closure = {
        "lane_a_reserve_challenge_passed": bool(lane_a_reserve_scorecard.get("bridge_hold", False)),
        "lane_b_reserve_challenge_passed": (
            float(lane_b_reserve_scorecard.get("all_case_metrics", {}).get("bridge_reason_exact_accuracy", 0.0)) >= 1.0
            and float(lane_b_reserve_scorecard.get("all_case_metrics", {}).get("route_consequence_visible_rate", 0.0))
            >= 1.0
        ),
        "reserve_challenges_pass": bool(screening_packet.get("reserve_challenges_pass", False)),
        "bridge_quality_collapsed_under_reserve": False,
        "route_consequence_collapsed_under_reserve": False,
    }

    return {
        "schema_id": "kt.operator.cohort0_successor_reentry_prep_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This packet binds the current successor evidence only as a strictly pre-Gate-D reentry-prep object. "
            "It does not reopen Gate D, authorize counted reentry, or open Gate E."
        ),
        "execution_status": "PASS__SUCCESSOR_REENTRY_PREP_PACKET_AUTHORED",
        "authority_and_boundary_header": {
            "gate_d_still_closed": True,
            "same_head_counted_reentry_still_blocked": True,
            "gate_e_still_closed": True,
            "packet_status": "STRICTLY_PRE_GATE_D_ONLY",
            "authorization_source_receipt_ref": source_refs["cross_lane_reentry_prep_screening_receipt_ref"],
            "authorization_source_packet_ref": source_refs["cross_lane_reentry_prep_screening_packet_ref"],
            "no_counted_claim_earned_yet": True,
        },
        "selected_successor_core": {
            "lead_bridge_candidate_id": controller.LEAD_BRIDGE_ID,
            "secondary_bridge_candidate_id": controller.SECONDARY_BRIDGE_ID,
            "guardrail_bridge_candidate_id": controller.GUARDRAIL_BRIDGE_ID,
            "fixed_harness_global_totals": dict(lane_a_scorecard.get("fixed_harness_global_totals", {})),
            "same_head_comparator_mode": "LOCKED__STATIC_ALPHA_COMPARATOR",
            "counted_boundary_status": "BLOCKED__CURRENT_LANE_HARDENED_CEILING",
        },
        "lane_a_evidence_spine": {
            "promoted_survivor_ids": lane_a_promoted_ids,
            "promoted_survivor_case_count": int(lane_a_scorecard.get("primary_survivor_case_count", 0)),
            "masked_companion_case_count": int(lane_a_scorecard.get("masked_companion_case_count", 0)),
            "full_bridge_hold": bool(lane_a_scorecard.get("full_bridge_hold", False)),
            "baseline_deltas": lane_a_lifts,
            "full_panel_metrics": lane_a_full_metrics,
            "fixed_harness_global_totals": dict(lane_a_scorecard.get("fixed_harness_global_totals", {})),
            "reserve_challenge_summary": lane_a_reserve_scorecard,
        },
        "lane_b_evidence_spine": {
            "hydrated_payload_provenance": {
                "hydrated_family_count": int(lane_b_hydrated_case_packet.get("hydrated_family_count", 0)),
                "hydrated_family_ids": [str(item.get("family_id", "")).strip() for item in hydrated_families],
                "visible_case_count": int(lane_b_hydration_receipt.get("hydrated_visible_case_count", 0)),
                "held_out_case_count": int(lane_b_hydration_receipt.get("hydrated_held_out_case_count", 0)),
            },
            "family_level_exact_admissible_summary": lane_b_family_summary,
            "overall_metrics": lane_b_overall_metrics,
            "route_consequence_visibility_summary": {
                "overall_rate": lane_b_overall_metrics.get("route_consequence_visible_rate", 0.0),
                "family_level_route_consequence_visibility_based_on_safety_surface": bool(
                    lane_b_scorecard.get("family_level_route_consequence_visibility_based_on_safety_surface", False)
                ),
            },
            "reserve_challenge_summary": lane_b_reserve_scorecard,
            "family_distinctness_and_novelty_support": {
                "promoted_family_ids": lane_b_promoted_ids,
                "rejected_overlap_items": lane_b_rejections,
            },
        },
        "cross_lane_comparative_verdict_section": {
            "lane_a_remains_numeric_benchmark_witness": bool(
                comparative_read.get("lane_a_remains_numeric_benchmark_witness", False)
            ),
            "lane_b_counts_as_materially_distinct_executed_theorem_strengthening_evidence": bool(
                comparative_read.get("lane_b_now_executed_on_materially_distinct_family_surface", False)
            ),
            "dominance_broadening_visible": bool(comparative_read.get("dominance_surface_broadening_visible", False)),
            "why_pre_gate_d_only": (
                "The current dual-lane bundle shows cross-lane bridge retention, fixed-harness consequence visibility, "
                "and passing reserve challenges, but it still does not reopen Gate D or make counted reentry admissible now."
            ),
        },
        "reserve_challenge_closure_section": reserve_challenge_closure,
        "non_claim_boundary_section": {
            "does_not_reopen_gate_d": True,
            "does_not_make_counted_reentry_admissible_now": True,
            "does_not_open_gate_e": True,
            "does_not_overrule_hardened_ceiling_law": True,
            "does_not_erase_prior_same_head_closure": True,
            "only_authorizes_next_gate_d_facing_preparatory_object": True,
        },
        "proofs_established": [
            "The redesign is no longer a one-lane-local story.",
            "The bridge+harness pair survives across both mutation and materially distinct family evidence.",
            "The branch now has enough bounded evidence breadth to justify a Gate D-facing admissibility screen.",
        ],
        "next_lawful_move_section": {
            "next_lawful_move": NEXT_LAWFUL_MOVE,
            "full_gate_d_readjudication_authorized_now": False,
        },
        "source_refs": source_refs,
        "subject_head": subject_head,
    }


def _build_receipt(*, subject_head: str, packet: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_successor_reentry_prep_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": "PASS__SUCCESSOR_REENTRY_PREP_PACKET_AUTHORED",
        "successor_reentry_prep_packet_authored": True,
        "pre_gate_d_only": True,
        "same_head_counted_reentry_admissible_now": False,
        "gate_d_reopened": False,
        "gate_e_open": False,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "subject_head": subject_head,
    }


def _build_report(*, packet: Dict[str, Any], receipt: Dict[str, Any]) -> str:
    lane_a = dict(packet.get("lane_a_evidence_spine", {}))
    lane_b = dict(packet.get("lane_b_evidence_spine", {}))
    compare = dict(packet.get("cross_lane_comparative_verdict_section", {}))
    reserve = dict(packet.get("reserve_challenge_closure_section", {}))
    return (
        "# Cohort0 Successor Reentry Prep Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Pre-Gate-D only: `{receipt.get('pre_gate_d_only', False)}`\n"
        f"- Counted reentry admissible now: `{receipt.get('same_head_counted_reentry_admissible_now', True)}`\n"
        f"- Gate D reopened: `{receipt.get('gate_d_reopened', True)}`\n"
        f"- Gate E open: `{receipt.get('gate_e_open', True)}`\n"
        f"- Next lawful move: `{receipt.get('next_lawful_move', '')}`\n\n"
        "## Selected Successor Core\n"
        f"- Lead bridge: `{packet.get('selected_successor_core', {}).get('lead_bridge_candidate_id', '')}`\n"
        f"- Secondary bridge: `{packet.get('selected_successor_core', {}).get('secondary_bridge_candidate_id', '')}`\n"
        f"- Guardrail bridge: `{packet.get('selected_successor_core', {}).get('guardrail_bridge_candidate_id', '')}`\n\n"
        "## Lane A Evidence Spine\n"
        f"- Promoted survivors: `{lane_a.get('promoted_survivor_ids', [])}`\n"
        f"- Full bridge hold: `{lane_a.get('full_bridge_hold', False)}`\n"
        f"- Full-panel exact: `{lane_a.get('full_panel_metrics', {}).get('selected_bridge_reason_exact_accuracy', 0.0)}`\n"
        f"- Full-panel admissible: `{lane_a.get('full_panel_metrics', {}).get('selected_bridge_reason_admissible_accuracy', 0.0)}`\n\n"
        "## Lane B Evidence Spine\n"
        f"- Hydrated family ids: `{lane_b.get('hydrated_payload_provenance', {}).get('hydrated_family_ids', [])}`\n"
        f"- Overall exact: `{lane_b.get('overall_metrics', {}).get('bridge_reason_exact_accuracy', 0.0)}`\n"
        f"- Overall admissible: `{lane_b.get('overall_metrics', {}).get('bridge_reason_admissible_accuracy', 0.0)}`\n"
        f"- Route consequence visibility: `{lane_b.get('route_consequence_visibility_summary', {}).get('overall_rate', 0.0)}`\n\n"
        "## Cross-Lane Verdict\n"
        f"- Lane A numeric benchmark: `{compare.get('lane_a_remains_numeric_benchmark_witness', False)}`\n"
        f"- Lane B materially distinct executed lane: `{compare.get('lane_b_counts_as_materially_distinct_executed_theorem_strengthening_evidence', False)}`\n"
        f"- Dominance broadening visible: `{compare.get('dominance_broadening_visible', False)}`\n\n"
        "## Reserve Challenge Closure\n"
        f"- Lane A reserve passed: `{reserve.get('lane_a_reserve_challenge_passed', False)}`\n"
        f"- Lane B reserve passed: `{reserve.get('lane_b_reserve_challenge_passed', False)}`\n"
        f"- Reserve challenges pass: `{reserve.get('reserve_challenges_pass', False)}`\n"
    )


def run(
    *,
    verdict_packet_path: Path,
    reentry_block_path: Path,
    successor_reentry_contract_path: Path,
    successor_readjudication_manifest_path: Path,
    lane_a_receipt_path: Path,
    lane_a_scorecard_path: Path,
    lane_b_hydration_receipt_path: Path,
    lane_b_hydrated_case_packet_path: Path,
    lane_b_receipt_path: Path,
    lane_b_scorecard_path: Path,
    cross_lane_packet_path: Path,
    screening_packet_path: Path,
    screening_receipt_path: Path,
    lane_a_reserve_scorecard_path: Path,
    lane_b_reserve_scorecard_path: Path,
    promotion_receipt_path: Path,
    rejection_receipt_path: Path,
    reports_root: Path,
) -> Dict[str, Any]:
    verdict_packet = _load_json_required(verdict_packet_path, label="hardened ceiling verdict packet")
    reentry_block = _load_json_required(reentry_block_path, label="gate d reentry block contract")
    successor_reentry_contract = _load_json_required(
        successor_reentry_contract_path, label="successor gate d reentry contract"
    )
    successor_readjudication_manifest = _load_json_required(
        successor_readjudication_manifest_path, label="successor gate d readjudication manifest"
    )
    lane_a_receipt = _load_json_required(lane_a_receipt_path, label="lane a promoted-survivor receipt")
    lane_a_scorecard = _load_json_required(lane_a_scorecard_path, label="lane a promoted-survivor scorecard")
    lane_b_hydration_receipt = _load_json_required(
        lane_b_hydration_receipt_path, label="lane b hydration receipt"
    )
    lane_b_hydrated_case_packet = _load_json_required(
        lane_b_hydrated_case_packet_path, label="lane b hydrated case packet"
    )
    lane_b_receipt = _load_json_required(lane_b_receipt_path, label="lane b family-level receipt")
    lane_b_scorecard = _load_json_required(lane_b_scorecard_path, label="lane b family-level scorecard")
    cross_lane_packet = _load_json_required(cross_lane_packet_path, label="cross-lane comparative packet")
    screening_packet = _load_json_required(screening_packet_path, label="cross-lane reentry-prep screening packet")
    screening_receipt = _load_json_required(screening_receipt_path, label="cross-lane reentry-prep screening receipt")
    lane_a_reserve_scorecard = _load_json_required(
        lane_a_reserve_scorecard_path, label="lane a reserve challenge scorecard"
    )
    lane_b_reserve_scorecard = _load_json_required(
        lane_b_reserve_scorecard_path, label="lane b reserve challenge scorecard"
    )
    promotion_receipt = _load_json_required(promotion_receipt_path, label="dual-lane promotion receipt")
    rejection_receipt = _load_json_required(rejection_receipt_path, label="dual-lane rejection receipt")

    _validate_inputs(
        verdict_packet=verdict_packet,
        reentry_block=reentry_block,
        successor_reentry_contract=successor_reentry_contract,
        successor_readjudication_manifest=successor_readjudication_manifest,
        lane_a_receipt=lane_a_receipt,
        lane_a_scorecard=lane_a_scorecard,
        lane_b_hydration_receipt=lane_b_hydration_receipt,
        lane_b_hydrated_case_packet=lane_b_hydrated_case_packet,
        lane_b_receipt=lane_b_receipt,
        lane_b_scorecard=lane_b_scorecard,
        cross_lane_packet=cross_lane_packet,
        screening_packet=screening_packet,
        screening_receipt=screening_receipt,
        lane_a_reserve_scorecard=lane_a_reserve_scorecard,
        lane_b_reserve_scorecard=lane_b_reserve_scorecard,
        promotion_receipt=promotion_receipt,
        rejection_receipt=rejection_receipt,
    )
    subject_head = _require_same_subject_head(
        (
            verdict_packet,
            reentry_block,
            successor_reentry_contract,
            successor_readjudication_manifest,
            lane_a_receipt,
            lane_a_scorecard,
            lane_b_hydration_receipt,
            lane_b_hydrated_case_packet,
            lane_b_receipt,
            lane_b_scorecard,
            cross_lane_packet,
            screening_packet,
            screening_receipt,
            lane_a_reserve_scorecard,
            lane_b_reserve_scorecard,
            promotion_receipt,
            rejection_receipt,
        )
    )

    source_refs = {
        "verdict_packet_ref": verdict_packet_path.as_posix(),
        "reentry_block_ref": reentry_block_path.as_posix(),
        "successor_reentry_contract_ref": successor_reentry_contract_path.as_posix(),
        "successor_readjudication_manifest_ref": successor_readjudication_manifest_path.as_posix(),
        "lane_a_receipt_ref": lane_a_receipt_path.as_posix(),
        "lane_a_scorecard_ref": lane_a_scorecard_path.as_posix(),
        "lane_b_hydration_receipt_ref": lane_b_hydration_receipt_path.as_posix(),
        "lane_b_hydrated_case_packet_ref": lane_b_hydrated_case_packet_path.as_posix(),
        "lane_b_receipt_ref": lane_b_receipt_path.as_posix(),
        "lane_b_scorecard_ref": lane_b_scorecard_path.as_posix(),
        "cross_lane_packet_ref": cross_lane_packet_path.as_posix(),
        "cross_lane_reentry_prep_screening_packet_ref": screening_packet_path.as_posix(),
        "cross_lane_reentry_prep_screening_receipt_ref": screening_receipt_path.as_posix(),
        "lane_a_reserve_scorecard_ref": lane_a_reserve_scorecard_path.as_posix(),
        "lane_b_reserve_scorecard_ref": lane_b_reserve_scorecard_path.as_posix(),
        "promotion_receipt_ref": promotion_receipt_path.as_posix(),
        "rejection_receipt_ref": rejection_receipt_path.as_posix(),
    }

    packet = _build_packet(
        subject_head=subject_head,
        lane_a_scorecard=lane_a_scorecard,
        lane_b_hydration_receipt=lane_b_hydration_receipt,
        lane_b_hydrated_case_packet=lane_b_hydrated_case_packet,
        lane_b_scorecard=lane_b_scorecard,
        cross_lane_packet=cross_lane_packet,
        screening_packet=screening_packet,
        screening_receipt=screening_receipt,
        lane_a_reserve_scorecard=lane_a_reserve_scorecard,
        lane_b_reserve_scorecard=lane_b_reserve_scorecard,
        promotion_receipt=promotion_receipt,
        rejection_receipt=rejection_receipt,
        source_refs=source_refs,
    )
    receipt = _build_receipt(subject_head=subject_head, packet=packet)

    reports_root.mkdir(parents=True, exist_ok=True)
    packet_path = reports_root / OUTPUT_PACKET
    receipt_path = reports_root / OUTPUT_RECEIPT
    report_path = reports_root / OUTPUT_REPORT

    write_json_stable(packet_path, packet)
    write_json_stable(receipt_path, receipt)
    _write_text(report_path, _build_report(packet=packet, receipt=receipt))

    return {
        "status": "PASS",
        "execution_status": receipt["execution_status"],
        "successor_reentry_prep_packet_authored": receipt["successor_reentry_prep_packet_authored"],
        "next_lawful_move": receipt["next_lawful_move"],
        "output_count": 3,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Author the strictly pre-Gate-D successor reentry-prep packet from the current cross-lane evidence bundle."
    )
    parser.add_argument("--verdict-packet", default=DEFAULT_VERDICT_PACKET_REL)
    parser.add_argument("--reentry-block", default=DEFAULT_REENTRY_BLOCK_REL)
    parser.add_argument("--successor-reentry-contract", default=DEFAULT_SUCCESSOR_REENTRY_CONTRACT_REL)
    parser.add_argument("--successor-readjudication-manifest", default=DEFAULT_SUCCESSOR_READJUDICATION_MANIFEST_REL)
    parser.add_argument("--lane-a-receipt", default=DEFAULT_LANE_A_RECEIPT_REL)
    parser.add_argument("--lane-a-scorecard", default=DEFAULT_LANE_A_SCORECARD_REL)
    parser.add_argument("--lane-b-hydration-receipt", default=DEFAULT_LANE_B_HYDRATION_RECEIPT_REL)
    parser.add_argument("--lane-b-hydrated-case-packet", default=DEFAULT_LANE_B_HYDRATED_CASE_PACKET_REL)
    parser.add_argument("--lane-b-receipt", default=DEFAULT_LANE_B_RECEIPT_REL)
    parser.add_argument("--lane-b-scorecard", default=DEFAULT_LANE_B_SCORECARD_REL)
    parser.add_argument("--cross-lane-packet", default=DEFAULT_CROSS_LANE_PACKET_REL)
    parser.add_argument("--screening-packet", default=DEFAULT_SCREENING_PACKET_REL)
    parser.add_argument("--screening-receipt", default=DEFAULT_SCREENING_RECEIPT_REL)
    parser.add_argument("--lane-a-reserve-scorecard", default=DEFAULT_LANE_A_RESERVE_SCORECARD_REL)
    parser.add_argument("--lane-b-reserve-scorecard", default=DEFAULT_LANE_B_RESERVE_SCORECARD_REL)
    parser.add_argument("--promotion-receipt", default=DEFAULT_PROMOTION_RECEIPT_REL)
    parser.add_argument("--rejection-receipt", default=DEFAULT_REJECTION_RECEIPT_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    args = parser.parse_args(argv)

    root = repo_root()
    result = run(
        verdict_packet_path=_resolve(root, args.verdict_packet),
        reentry_block_path=_resolve(root, args.reentry_block),
        successor_reentry_contract_path=_resolve(root, args.successor_reentry_contract),
        successor_readjudication_manifest_path=_resolve(root, args.successor_readjudication_manifest),
        lane_a_receipt_path=_resolve(root, args.lane_a_receipt),
        lane_a_scorecard_path=_resolve(root, args.lane_a_scorecard),
        lane_b_hydration_receipt_path=_resolve(root, args.lane_b_hydration_receipt),
        lane_b_hydrated_case_packet_path=_resolve(root, args.lane_b_hydrated_case_packet),
        lane_b_receipt_path=_resolve(root, args.lane_b_receipt),
        lane_b_scorecard_path=_resolve(root, args.lane_b_scorecard),
        cross_lane_packet_path=_resolve(root, args.cross_lane_packet),
        screening_packet_path=_resolve(root, args.screening_packet),
        screening_receipt_path=_resolve(root, args.screening_receipt),
        lane_a_reserve_scorecard_path=_resolve(root, args.lane_a_reserve_scorecard),
        lane_b_reserve_scorecard_path=_resolve(root, args.lane_b_reserve_scorecard),
        promotion_receipt_path=_resolve(root, args.promotion_receipt),
        rejection_receipt_path=_resolve(root, args.rejection_receipt),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in (
        "status",
        "execution_status",
        "successor_reentry_prep_packet_authored",
        "next_lawful_move",
        "output_count",
        "receipt_path",
        "subject_head",
    ):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
