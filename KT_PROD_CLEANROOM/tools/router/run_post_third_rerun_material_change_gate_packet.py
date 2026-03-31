from __future__ import annotations

import argparse
import json
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.router.run_verified_entrant_lab_scorecard import _load_json_dict, _resolve


def _validate_ceiling_reconsideration_input(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != "kt.router_readiness_reconsideration_input.v1":
        raise RuntimeError("FAIL_CLOSED: ceiling reconsideration input schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: ceiling reconsideration input mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: ceiling reconsideration input must be PASS")


def _validate_candidate_refresh(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != "kt.fourth_terminal_lab_readiness_refresh_packet.v1":
        raise RuntimeError("FAIL_CLOSED: fourth terminal refresh packet schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: fourth terminal refresh packet mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: fourth terminal refresh packet must be PASS")


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


def build_post_third_rerun_material_change_gate_packet(
    *,
    ceiling_reconsideration_input: Dict[str, Any],
    candidate_refresh_packet: Dict[str, Any],
    ceiling_reconsideration_input_ref: str,
    candidate_refresh_packet_ref: str,
) -> Dict[str, Any]:
    _validate_ceiling_reconsideration_input(ceiling_reconsideration_input)
    _validate_candidate_refresh(candidate_refresh_packet)

    ceiling_summary = ceiling_reconsideration_input.get("candidate_summary")
    candidate_questions = candidate_refresh_packet.get("questions")
    candidate_terminal_summary = candidate_refresh_packet.get("terminal_summary")
    candidate_route_summary = candidate_refresh_packet.get("route_summary")
    if not isinstance(ceiling_summary, dict):
        raise RuntimeError("FAIL_CLOSED: ceiling reconsideration candidate summary missing")
    if not isinstance(candidate_questions, dict):
        raise RuntimeError("FAIL_CLOSED: candidate refresh questions missing")
    if not isinstance(candidate_terminal_summary, dict) or not isinstance(candidate_route_summary, dict):
        raise RuntimeError("FAIL_CLOSED: candidate refresh summaries missing")

    ceiling_head = str(ceiling_summary.get("candidate_lab_head", "")).strip()
    candidate_head = str(candidate_refresh_packet.get("source_lab_head", "")).strip()

    ceiling_terminals = _ordered_unique(ceiling_summary.get("combined_terminal_adapters", []))
    if not ceiling_terminals:
        ceiling_terminals = _ordered_unique(ceiling_summary.get("terminal_adapters", []))
    candidate_terminals = _ordered_unique(candidate_terminal_summary.get("combined_terminal_adapters", []))

    ceiling_route_pairs = _ordered_unique(ceiling_summary.get("route_pairs", []))
    candidate_route_pairs = _ordered_unique(candidate_route_summary.get("combined_route_pairs", []))

    new_terminal_adapters = [item for item in candidate_terminals if item not in ceiling_terminals]
    new_route_pairs = [item for item in candidate_route_pairs if item not in ceiling_route_pairs]

    same_head_as_ceiling = ceiling_head == candidate_head
    candidate_core_constraints_confirmed = all(
        bool(candidate_questions.get(key, False))
        for key in (
            "same_head_across_refresh",
            "broader_reruns_confirmed_across_all_terminal_paths",
            "same_head_consistency_preserved_across_all_terminal_paths",
            "shadow_constraints_preserved_across_all_terminal_paths",
            "fresh_verified_entrants_preserved_across_all_terminal_paths",
            "tournament_like_constraints_passed_across_all_terminal_paths",
            "distinct_route_topology_visible_across_all_terminal_paths",
            "fourth_terminal_diversity_visible",
        )
    )
    introduced_new_terminal_adapter = len(new_terminal_adapters) > 0
    expanded_terminal_adapter_count = len(candidate_terminals) > len(ceiling_terminals)
    introduced_new_route_pair = len(new_route_pairs) > 0
    expanded_route_pair_count = len(candidate_route_pairs) > len(ceiling_route_pairs)
    same_terminal_adapter_set_as_ceiling = set(candidate_terminals) == set(ceiling_terminals)
    same_route_pair_set_as_ceiling = set(candidate_route_pairs) == set(ceiling_route_pairs)
    same_preserved_ceiling_story_under_new_label = (
        candidate_core_constraints_confirmed
        and same_terminal_adapter_set_as_ceiling
        and same_route_pair_set_as_ceiling
    )

    material_change_earned = (
        candidate_core_constraints_confirmed
        and not same_head_as_ceiling
        and introduced_new_terminal_adapter
        and expanded_terminal_adapter_count
    )
    semantic_bypass_risk = not material_change_earned and same_preserved_ceiling_story_under_new_label

    blockers: List[str] = []
    if same_head_as_ceiling:
        blockers.append("CANDIDATE_REFRESH_IS_SAME_LAB_HEAD_AS_POST_RERUN_CEILING")
    if not candidate_core_constraints_confirmed:
        blockers.append("CANDIDATE_REFRESH_CORE_CONSTRAINTS_NOT_CONFIRMED")
    if not introduced_new_terminal_adapter:
        blockers.append("NO_NEW_TERMINAL_ADAPTER_BEYOND_POST_RERUN_CEILING")
    if not expanded_terminal_adapter_count:
        blockers.append("TERMINAL_ADAPTER_COUNT_NOT_EXPANDED_BEYOND_POST_RERUN_CEILING")
    if not introduced_new_route_pair:
        blockers.append("NO_NEW_ROUTE_PAIR_BEYOND_POST_RERUN_CEILING")
    if semantic_bypass_risk:
        blockers.append("SAME_PRESERVED_POST_RERUN_CEILING_STORY__NOT_MATERIAL_CHANGE")

    posture = (
        "READY_FOR_POST_RERUN_ROUTER_READINESS_RECONSIDERATION_INPUT_CONSIDERATION"
        if material_change_earned
        else "HOLD_LAB_ONLY_PENDING_POST_RERUN_MATERIAL_CHANGE"
    )

    return {
        "schema_id": "kt.post_third_rerun_material_change_gate_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "claim_boundary": (
            "This packet is lab-only and noncanonical. It does not reopen the counted lane, does not count as R5 evidence, "
            "does not earn router superiority, and cannot unlock R6. Its only job is to say whether a new post-third-rerun "
            "lab head is materially different enough from the preserved three-terminal reconsideration ceiling to justify "
            "preparing a later reconsideration input again."
        ),
        "questions": {
            "same_head_as_post_rerun_ceiling": same_head_as_ceiling,
            "candidate_core_constraints_confirmed": candidate_core_constraints_confirmed,
            "introduced_new_terminal_adapter": introduced_new_terminal_adapter,
            "expanded_terminal_adapter_count": expanded_terminal_adapter_count,
            "introduced_new_route_pair": introduced_new_route_pair,
            "expanded_route_pair_count": expanded_route_pair_count,
            "same_terminal_adapter_set_as_post_rerun_ceiling": same_terminal_adapter_set_as_ceiling,
            "same_route_pair_set_as_post_rerun_ceiling": same_route_pair_set_as_ceiling,
            "same_preserved_post_rerun_ceiling_story_under_new_label": same_preserved_ceiling_story_under_new_label,
            "semantic_bypass_risk": semantic_bypass_risk,
            "material_change_earned": material_change_earned
        },
        "gate_posture": posture,
        "counted_lane_recommendation": "KEEP_COUNTED_LANE_CLOSED",
        "later_reconsideration_gate": (
            "Only when material_change_earned = true may a later post-rerun router-readiness reconsideration input be prepared. "
            "Even then, counted reopening remains separate and requires its own lawful decision surface."
        ),
        "blockers": blockers,
        "source_packet_refs": {
            "ceiling_reconsideration_input_ref": ceiling_reconsideration_input_ref,
            "candidate_refresh_packet_ref": candidate_refresh_packet_ref
        },
        "ceiling_summary": {
            "ceiling_lab_head": ceiling_head,
            "terminal_adapters": ceiling_terminals,
            "route_pairs": ceiling_route_pairs,
            "terminal_adapter_count": len(ceiling_terminals),
            "route_pair_count": len(ceiling_route_pairs)
        },
        "candidate_summary": {
            "candidate_lab_head": candidate_head,
            "terminal_adapters": candidate_terminals,
            "route_pairs": candidate_route_pairs,
            "terminal_adapter_count": len(candidate_terminals),
            "route_pair_count": len(candidate_route_pairs),
            "new_terminal_adapters": new_terminal_adapters,
            "new_route_pairs": new_route_pairs
        }
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Gate a new post-third-rerun router material-change candidate against the preserved three-terminal reconsideration ceiling."
    )
    parser.add_argument("--ceiling-reconsideration-input", required=True)
    parser.add_argument("--candidate-refresh-packet", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    ceiling_ref = str(args.ceiling_reconsideration_input)
    candidate_ref = str(args.candidate_refresh_packet)
    ceiling_packet = _load_json_dict(_resolve(root, ceiling_ref), name="ceiling_reconsideration_input")
    candidate_packet = _load_json_dict(_resolve(root, candidate_ref), name="candidate_refresh_packet")

    packet = build_post_third_rerun_material_change_gate_packet(
        ceiling_reconsideration_input=ceiling_packet,
        candidate_refresh_packet=candidate_packet,
        ceiling_reconsideration_input_ref=ceiling_ref,
        candidate_refresh_packet_ref=candidate_ref,
    )
    output_path = _resolve(root, str(args.output))
    write_json_stable(output_path, packet)
    print(json.dumps(packet["questions"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
