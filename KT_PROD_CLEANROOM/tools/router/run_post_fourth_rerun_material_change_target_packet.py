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
        != "GATE_D_POST_FOURTH_RERUN_STATIC_HOLD__COUNTED_LANE_CLOSED"
    ):
        raise RuntimeError("FAIL_CLOSED: current state is not the post-fourth-rerun static hold")
    if str(packet.get("next_counted_workstream_id", "")).strip() != "B04_R6_LEARNED_ROUTER_AUTHORIZATION":
        raise RuntimeError("FAIL_CLOSED: next counted workstream is not blocked R6")
    if bool(packet.get("repo_state_executable_now", False)):
        raise RuntimeError("FAIL_CLOSED: counted lane must be closed for post-fourth-rerun targeting")


def _validate_refresh_packet(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != "kt.fourth_terminal_lab_readiness_refresh_packet.v1":
        raise RuntimeError("FAIL_CLOSED: fourth-terminal lab readiness refresh packet schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: fourth-terminal lab readiness refresh packet mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: fourth-terminal lab readiness refresh packet must be PASS")

    questions = packet.get("questions")
    terminal_summary = packet.get("terminal_summary")
    route_summary = packet.get("route_summary")
    if not isinstance(questions, dict) or not isinstance(terminal_summary, dict) or not isinstance(route_summary, dict):
        raise RuntimeError("FAIL_CLOSED: fourth-terminal lab readiness refresh packet summaries missing")

    required_true = (
        "same_head_across_refresh",
        "broader_reruns_confirmed_across_all_terminal_paths",
        "same_head_consistency_preserved_across_all_terminal_paths",
        "shadow_constraints_preserved_across_all_terminal_paths",
        "fresh_verified_entrants_preserved_across_all_terminal_paths",
        "tournament_like_constraints_passed_across_all_terminal_paths",
        "distinct_route_topology_visible_across_all_terminal_paths",
        "fourth_terminal_diversity_visible",
    )
    if not all(bool(questions.get(key, False)) for key in required_true):
        raise RuntimeError("FAIL_CLOSED: refresh packet does not preserve the four-terminal lab ceiling")


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
        return "the current preserved terminal set"
    if len(quoted) == 1:
        return quoted[0]
    if len(quoted) == 2:
        return f"{quoted[0]} and {quoted[1]}"
    return ", ".join(quoted[:-1]) + f", and {quoted[-1]}"


def build_post_fourth_rerun_material_change_target_packet(
    *,
    current_state_overlay: Dict[str, Any],
    fourth_terminal_refresh_packet: Dict[str, Any],
    current_state_overlay_ref: str,
    fourth_terminal_refresh_packet_ref: str,
) -> Dict[str, Any]:
    _validate_current_state_overlay(current_state_overlay)
    _validate_refresh_packet(fourth_terminal_refresh_packet)

    lawful_standing = current_state_overlay["current_lawful_gate_standing"]
    completed_tranches_raw = lawful_standing.get("completed_tranches")
    if not isinstance(completed_tranches_raw, list):
        raise RuntimeError("FAIL_CLOSED: completed tranches missing from current state overlay")
    completed_tranches = {str(item).strip() for item in completed_tranches_raw}

    missing_non_router_core = [
        tranche for tranche in _NON_ROUTER_GATE_D_CORE_TRANCHES if tranche not in completed_tranches
    ]
    pivot_branch_available = len(missing_non_router_core) > 0

    terminal_summary = fourth_terminal_refresh_packet["terminal_summary"]
    route_summary = fourth_terminal_refresh_packet["route_summary"]
    refresh_questions = fourth_terminal_refresh_packet["questions"]

    frozen_terminals = _ordered_unique(terminal_summary.get("combined_terminal_adapters", []))
    frozen_route_pairs = _ordered_unique(route_summary.get("combined_route_pairs", []))
    frozen_terminal_count = len(frozen_terminals)
    frozen_route_pair_count = len(frozen_route_pairs)
    frozen_lab_head = str(fourth_terminal_refresh_packet.get("source_lab_head", "")).strip()

    material_change_target_sentence = (
        "On a new lab head, introduce at least one downstream terminal adapter beyond "
        f"{_format_terminals(frozen_terminals)}, expand the combined terminal-adapter count beyond {frozen_terminal_count}, "
        "and keep rerun, fresh-entrant, shadow, and tournament-like constraints green while preserving the current "
        "four-terminal paths so a later material-change gate can honestly return `material_change_earned = true`."
    )

    router_branch_selected = not pivot_branch_available
    branch_selection_posture = (
        "ROUTER_BRANCH_ONLY__NO_EARLIER_NON_ROUTER_GATE_D_PIVOT_AVAILABLE"
        if router_branch_selected
        else "NON_ROUTER_GATE_D_PIVOT_STILL_AVAILABLE"
    )

    return {
        "schema_id": "kt.post_fourth_rerun_material_change_target_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "claim_boundary": (
            "This packet is lab-only and noncanonical. It does not reopen the counted lane, does not count as R5 evidence, "
            "does not earn router superiority, and cannot unlock R6. Its only job is to name the exact material-change "
            "target the router branch would have to earn after the fourth counted static hold before any later reconsideration "
            "path can lawfully begin again."
        ),
        "branch_selection_posture": branch_selection_posture,
        "questions": {
            "pivot_branch_available": pivot_branch_available,
            "router_branch_selected": router_branch_selected,
            "non_router_gate_d_core_complete": len(missing_non_router_core) == 0,
            "counted_lane_closed_now": True,
            "static_baseline_still_canonical": True,
            "requires_new_lab_head": True,
            "requires_new_terminal_adapter_beyond_current_four": True,
            "requires_terminal_adapter_count_beyond_current_four": True,
            "requires_preserving_current_four_terminal_constraints": True,
            "route_pair_only_novelty_would_still_fail": True,
            "validator_only_or_hold_only_changes_would_still_fail": True,
        },
        "current_router_hold_summary": {
            "counted_lane_posture": "KEEP_COUNTED_LANE_CLOSED",
            "static_baseline_status": "CANONICAL",
            "next_in_order": str(current_state_overlay.get("next_counted_workstream_id", "")).strip(),
            "next_in_order_status": "BLOCKED_IN_LAW",
            "frozen_four_terminal_lab_head": frozen_lab_head,
            "frozen_terminal_adapters": frozen_terminals,
            "frozen_route_pairs": frozen_route_pairs,
            "frozen_route_pair_count": frozen_route_pair_count,
        },
        "router_material_change_target_sentence": material_change_target_sentence,
        "material_change_requirements": [
            "Use a new lab head rather than reusing the preserved four-terminal head.",
            f"Introduce at least one downstream terminal adapter beyond the current frozen set of {_format_terminals(frozen_terminals)}.",
            f"Expand the combined downstream terminal-adapter count beyond {frozen_terminal_count}.",
            "Keep rerun, fresh-entrant, shadow, and tournament-like constraints green on that new head.",
            "Preserve the currently confirmed four-terminal paths instead of collapsing back to a smaller terminal set.",
            "Do not rely on route-pair novelty alone; the next gate still fails closed if terminal diversity does not expand again.",
        ],
        "non_forward_motion_classes": [
            "Another counted rerun by momentum without a new lab material-change cycle.",
            "Another guard or freeze packet without a new downstream terminal adapter.",
            "Route-pair novelty that still terminates inside the same preserved four-terminal set.",
            "Validator-only, wording-only, or hold-only changes without a new lab head and new terminal breadth.",
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
        "preserved_four_terminal_refresh_summary": {
            "source_lab_head": frozen_lab_head,
            "terminal_adapter_count": frozen_terminal_count,
            "route_pair_count": frozen_route_pair_count,
            "constraints_preserved": all(bool(refresh_questions.get(key, False)) for key in refresh_questions),
        },
        "later_reconsideration_sequence_if_earned": [
            "Build a new material-change gate packet against the preserved four-terminal ceiling and require material_change_earned = true.",
            "Re-emit the same-head single-path guard on the actual candidate head and require PASS.",
            "Re-emit the preserved-basis receipt on that same candidate head and require PASS as non-authority only.",
            "Prepare the reconsideration input only through the sanctioned emitter entrypoint already bound in the hold chain.",
            "Consume the reconsideration input only through the sanctioned validator entrypoint already bound in the hold chain.",
            "Only after that separate reconsideration path succeeds may a later counted reopening surface be considered.",
        ],
        "source_packet_refs": {
            "current_state_overlay_ref": current_state_overlay_ref,
            "fourth_terminal_refresh_packet_ref": fourth_terminal_refresh_packet_ref,
        },
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Emit the next post-fourth-rerun lab-only router material-change target required before any later reconsideration path can lawfully reopen."
    )
    parser.add_argument("--current-state-overlay", required=True)
    parser.add_argument("--fourth-terminal-refresh-packet", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    overlay_ref = str(args.current_state_overlay)
    refresh_ref = str(args.fourth_terminal_refresh_packet)
    overlay_packet = _load_json_dict(_resolve(root, overlay_ref), name="current_campaign_state_overlay")
    refresh_packet = _load_json_dict(_resolve(root, refresh_ref), name="fourth_terminal_lab_readiness_refresh_packet")

    packet = build_post_fourth_rerun_material_change_target_packet(
        current_state_overlay=overlay_packet,
        fourth_terminal_refresh_packet=refresh_packet,
        current_state_overlay_ref=overlay_ref,
        fourth_terminal_refresh_packet_ref=refresh_ref,
    )
    output_path = _resolve(root, str(args.output))
    write_json_stable(output_path, packet)
    print(json.dumps(packet["questions"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
