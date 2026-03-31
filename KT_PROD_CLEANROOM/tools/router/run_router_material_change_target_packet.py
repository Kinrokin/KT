from __future__ import annotations

import argparse
import json
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.router.run_verified_entrant_lab_scorecard import _load_json_dict, _resolve


_NON_ROUTER_GATE_D_CORE_TRANCHES = (
    "B04_R1_CRUCIBLE_PRESSURE_LAW_RATIFICATION",
    "B04_R2_ADAPTER_LIFECYCLE_LAW_RATIFICATION",
    "B04_R3_TOURNAMENT_PROMOTION_MERGE_LAW_RATIFICATION",
)


def _validate_current_state_overlay(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != "kt.current_campaign_state_overlay.v1":
        raise RuntimeError("FAIL_CLOSED: current campaign state overlay schema mismatch")

    lawful_standing = packet.get("current_lawful_gate_standing")
    if not isinstance(lawful_standing, dict):
        raise RuntimeError("FAIL_CLOSED: current lawful gate standing missing")

    if (
        str(lawful_standing.get("inter_gate_state", "")).strip()
        != "GATE_D_LAB_READINESS_RECONSIDERATION_GATE_FROZEN__COUNTED_LANE_CLOSED"
    ):
        raise RuntimeError("FAIL_CLOSED: current state is not the frozen Gate D lab reconsideration hold")
    if str(packet.get("next_counted_workstream_id", "")).strip() != "B04_R6_LEARNED_ROUTER_AUTHORIZATION":
        raise RuntimeError("FAIL_CLOSED: next counted workstream is not blocked R6")


def _validate_gate_packet(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != "kt.lab_readiness_reconsideration_gate_packet.v1":
        raise RuntimeError("FAIL_CLOSED: lab readiness reconsideration gate packet schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: lab readiness reconsideration gate packet mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: lab readiness reconsideration gate packet must be PASS")

    questions = packet.get("questions")
    if not isinstance(questions, dict):
        raise RuntimeError("FAIL_CLOSED: lab readiness reconsideration gate questions missing")

    if bool(questions.get("material_change_earned", False)):
        raise RuntimeError("FAIL_CLOSED: current gate already earned material change")
    if str(packet.get("gate_posture", "")).strip() != "HOLD_LAB_CEILING__NO_MATERIAL_CHANGE_YET":
        raise RuntimeError("FAIL_CLOSED: gate posture is not the expected frozen hold")


def _ordered_unique(items: Sequence[str]) -> List[str]:
    seen: set[str] = set()
    ordered: List[str] = []
    for item in items:
        cleaned = str(item).strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        ordered.append(cleaned)
    return ordered


def _format_terminals(terminals: Sequence[str]) -> str:
    quoted = [f"`{item}`" for item in _ordered_unique(terminals)]
    if not quoted:
        return "the current frozen terminal set"
    if len(quoted) == 1:
        return quoted[0]
    if len(quoted) == 2:
        return f"{quoted[0]} and {quoted[1]}"
    return ", ".join(quoted[:-1]) + f", and {quoted[-1]}"


def build_router_material_change_target_packet(
    *,
    current_state_overlay: Dict[str, Any],
    reconsideration_gate_packet: Dict[str, Any],
    current_state_overlay_ref: str,
    reconsideration_gate_packet_ref: str,
) -> Dict[str, Any]:
    _validate_current_state_overlay(current_state_overlay)
    _validate_gate_packet(reconsideration_gate_packet)

    lawful_standing = current_state_overlay["current_lawful_gate_standing"]
    completed_tranches_raw = lawful_standing.get("completed_tranches")
    if not isinstance(completed_tranches_raw, list):
        raise RuntimeError("FAIL_CLOSED: completed tranches missing from current state overlay")
    completed_tranches = {str(item).strip() for item in completed_tranches_raw}

    missing_non_router_core = [
        tranche for tranche in _NON_ROUTER_GATE_D_CORE_TRANCHES if tranche not in completed_tranches
    ]
    pivot_branch_available = len(missing_non_router_core) > 0

    ceiling_summary = reconsideration_gate_packet.get("ceiling_summary")
    candidate_summary = reconsideration_gate_packet.get("candidate_summary")
    questions = reconsideration_gate_packet.get("questions")
    if not isinstance(ceiling_summary, dict) or not isinstance(candidate_summary, dict) or not isinstance(questions, dict):
        raise RuntimeError("FAIL_CLOSED: reconsideration gate packet summaries missing")

    frozen_terminals = _ordered_unique(ceiling_summary.get("terminal_adapters", []))
    frozen_terminal_count = len(frozen_terminals)
    blocked_candidate_head = str(candidate_summary.get("candidate_lab_head", "")).strip()
    frozen_ceiling_head = str(ceiling_summary.get("ceiling_lab_head", "")).strip()

    material_change_target_sentence = (
        "On a new lab head, introduce at least one downstream terminal adapter beyond "
        f"{_format_terminals(frozen_terminals)}, expand the terminal-adapter count beyond {frozen_terminal_count}, "
        "and keep rerun, fresh-entrant, shadow, and tournament-like constraints green so the reconsideration gate can "
        "honestly return `material_change_earned = true`."
    )

    router_branch_selected = not pivot_branch_available
    branch_selection_posture = (
        "ROUTER_BRANCH_ONLY__NO_EARLIER_NON_ROUTER_GATE_D_PIVOT_AVAILABLE"
        if router_branch_selected
        else "NON_ROUTER_GATE_D_PIVOT_STILL_AVAILABLE"
    )

    blockers = [
        str(item).strip()
        for item in reconsideration_gate_packet.get("blockers", [])
        if str(item).strip()
    ]

    return {
        "schema_id": "kt.router_material_change_target_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "claim_boundary": (
            "This packet is lab-only and noncanonical. It does not reopen the counted lane, does not count as R5 evidence, "
            "does not earn router superiority, and cannot unlock R6. Its only job is to name the exact material-change "
            "target the router branch would have to earn before any later reconsideration path can lawfully begin again."
        ),
        "branch_selection_posture": branch_selection_posture,
        "questions": {
            "pivot_branch_available": pivot_branch_available,
            "router_branch_selected": router_branch_selected,
            "non_router_gate_d_core_complete": len(missing_non_router_core) == 0,
            "current_gate_holds": str(reconsideration_gate_packet.get("gate_posture", "")).strip()
            == "HOLD_LAB_CEILING__NO_MATERIAL_CHANGE_YET",
            "material_change_earned_now": bool(questions.get("material_change_earned", False)),
            "same_head_reuse_is_current_blocker": bool(questions.get("same_head_as_ceiling", False)),
            "new_terminal_adapter_is_current_blocker": not bool(questions.get("introduced_new_terminal_adapter", False)),
            "terminal_count_expansion_is_current_blocker": not bool(
                questions.get("expanded_terminal_adapter_count", False)
            ),
            "route_pair_only_novelty_would_still_fail": True,
        },
        "current_router_hold_summary": {
            "counted_lane_posture": "KEEP_COUNTED_LANE_CLOSED",
            "static_baseline_status": "CANONICAL",
            "next_in_order": str(current_state_overlay.get("next_counted_workstream_id", "")).strip(),
            "next_in_order_status": "BLOCKED_IN_LAW",
            "frozen_ceiling_lab_head": frozen_ceiling_head,
            "blocked_candidate_lab_head": blocked_candidate_head,
            "current_gate_blockers": blockers,
        },
        "router_material_change_target_sentence": material_change_target_sentence,
        "material_change_requirements": [
            "Use a new lab head rather than reusing the frozen ceiling head.",
            f"Introduce at least one downstream terminal adapter beyond the current frozen set of {_format_terminals(frozen_terminals)}.",
            f"Expand the combined downstream terminal-adapter count beyond {frozen_terminal_count}.",
            "Keep rerun, fresh-entrant, shadow, and tournament-like constraints green on that new head.",
            "Do not rely on route-pair novelty alone; the gate still fails closed if terminal diversity does not expand.",
        ],
        "non_forward_motion_classes": [
            "Another hold or freeze packet without a new downstream terminal adapter.",
            "A new label on the same preserved ceiling story.",
            "Route-pair novelty that still terminates in the same frozen terminal set.",
            "Any counted-lane narration before the reconsideration gate actually returns material_change_earned = true.",
        ],
        "pivot_branch_summary": {
            "available": pivot_branch_available,
            "missing_non_router_gate_d_core_tranches": missing_non_router_core,
            "why_not_available_now": (
                "Earlier non-router Gate D ratification tranches are already complete, and the live counted sequence already sits at blocked R6."
                if not pivot_branch_available
                else "At least one earlier non-router Gate D core tranche is still unfinished."
            ),
        },
        "later_reconsideration_sequence_if_earned": [
            "Re-emit the same-head single-path guard on the actual candidate head and require PASS.",
            "Re-emit the preserved-basis receipt on that same candidate head and require PASS as non-authority only.",
            "Prepare the reconsideration input only through KT_PROD_CLEANROOM/tools/router/run_router_readiness_reconsideration_input.py.",
            "Consume the reconsideration input only through KT_PROD_CLEANROOM/tools/operator/router_readiness_reconsideration_input_validate.py.",
            "Only after that separate reconsideration path succeeds may a later counted reopening surface be considered.",
        ],
        "source_packet_refs": {
            "current_state_overlay_ref": current_state_overlay_ref,
            "reconsideration_gate_packet_ref": reconsideration_gate_packet_ref,
        },
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Emit the current lab-only router material-change target required to beat the frozen reconsideration ceiling."
    )
    parser.add_argument("--current-state-overlay", required=True)
    parser.add_argument("--reconsideration-gate-packet", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    overlay_ref = str(args.current_state_overlay)
    gate_ref = str(args.reconsideration_gate_packet)
    overlay_packet = _load_json_dict(_resolve(root, overlay_ref), name="current_campaign_state_overlay")
    gate_packet = _load_json_dict(_resolve(root, gate_ref), name="lab_readiness_reconsideration_gate_packet")

    packet = build_router_material_change_target_packet(
        current_state_overlay=overlay_packet,
        reconsideration_gate_packet=gate_packet,
        current_state_overlay_ref=overlay_ref,
        reconsideration_gate_packet_ref=gate_ref,
    )
    output_path = _resolve(root, str(args.output))
    write_json_stable(output_path, packet)
    print(json.dumps(packet["questions"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
