from __future__ import annotations

import argparse
import json
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.router.run_verified_entrant_lab_scorecard import _load_json_dict, _resolve


def _validate_ceiling_packet(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != "kt.lab_readiness_ceiling_packet.v1":
        raise RuntimeError("FAIL_CLOSED: lab readiness ceiling packet schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: lab readiness ceiling packet mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: lab readiness ceiling packet must be PASS")


def _validate_refresh_packet(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != "kt.later_lab_readiness_refresh_packet.v1":
        raise RuntimeError("FAIL_CLOSED: later lab readiness refresh packet schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: later lab readiness refresh packet mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: later lab readiness refresh packet must be PASS")


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


def _route_pairs_from_refresh(packet: Dict[str, Any]) -> List[str]:
    source_summaries = packet.get("source_summaries")
    if not isinstance(source_summaries, dict):
        raise RuntimeError("FAIL_CLOSED: refresh packet source_summaries missing")

    route_pairs: List[str] = []
    for key in ("code_route_topology_summary", "math_route_topology_summary"):
        summary = source_summaries.get(key)
        if not isinstance(summary, dict):
            continue
        route_pairs.extend(str(item).strip() for item in summary.get("combined_route_pairs", []))
    return _ordered_unique(route_pairs)


def _terminal_adapters_from_refresh(packet: Dict[str, Any]) -> List[str]:
    terminal_summary = packet.get("terminal_summary")
    if not isinstance(terminal_summary, dict):
        raise RuntimeError("FAIL_CLOSED: refresh packet terminal_summary missing")
    return _ordered_unique(terminal_summary.get("combined_terminal_adapters", []))


def _ceiling_terminal_adapters(packet: Dict[str, Any]) -> List[str]:
    source_refresh_summary = packet.get("source_refresh_summary")
    if not isinstance(source_refresh_summary, dict):
        raise RuntimeError("FAIL_CLOSED: ceiling packet source_refresh_summary missing")

    terminal_summary = source_refresh_summary.get("terminal_summary")
    if not isinstance(terminal_summary, dict):
        raise RuntimeError("FAIL_CLOSED: ceiling packet terminal_summary missing")
    return _ordered_unique(terminal_summary.get("combined_terminal_adapters", []))


def _ceiling_route_pairs(packet: Dict[str, Any]) -> List[str]:
    source_refresh_summary = packet.get("source_refresh_summary")
    if not isinstance(source_refresh_summary, dict):
        raise RuntimeError("FAIL_CLOSED: ceiling packet source_refresh_summary missing")

    source_summaries = source_refresh_summary.get("source_summaries")
    if not isinstance(source_summaries, dict):
        raise RuntimeError("FAIL_CLOSED: ceiling packet source_summaries missing")

    route_pairs: List[str] = []
    for key in ("code_route_topology_summary", "math_route_topology_summary"):
        summary = source_summaries.get(key)
        if not isinstance(summary, dict):
            continue
        route_pairs.extend(str(item).strip() for item in summary.get("combined_route_pairs", []))
    return _ordered_unique(route_pairs)


def build_lab_readiness_reconsideration_gate_packet(
    *,
    ceiling_packet: Dict[str, Any],
    candidate_refresh_packet: Dict[str, Any],
    ceiling_packet_ref: str,
    candidate_refresh_packet_ref: str,
) -> Dict[str, Any]:
    _validate_ceiling_packet(ceiling_packet)
    _validate_refresh_packet(candidate_refresh_packet)

    ceiling_heads = ceiling_packet.get("source_lab_heads")
    candidate_heads = candidate_refresh_packet.get("source_lab_heads")
    candidate_questions = candidate_refresh_packet.get("questions")
    if not isinstance(ceiling_heads, dict) or not isinstance(candidate_heads, dict):
        raise RuntimeError("FAIL_CLOSED: source_lab_heads missing")
    if not isinstance(candidate_questions, dict):
        raise RuntimeError("FAIL_CLOSED: candidate refresh questions missing")

    ceiling_head = str(ceiling_heads.get("code_terminal_lab_head", "")).strip()
    candidate_head = str(candidate_heads.get("code_terminal_lab_head", "")).strip()

    ceiling_terminals = _ceiling_terminal_adapters(ceiling_packet)
    candidate_terminals = _terminal_adapters_from_refresh(candidate_refresh_packet)
    ceiling_route_pairs = _ceiling_route_pairs(ceiling_packet)
    candidate_route_pairs = _route_pairs_from_refresh(candidate_refresh_packet)

    new_terminal_adapters = [item for item in candidate_terminals if item not in ceiling_terminals]
    new_route_pairs = [item for item in candidate_route_pairs if item not in ceiling_route_pairs]

    same_head_as_ceiling = ceiling_head == candidate_head
    candidate_core_constraints_confirmed = all(
        bool(candidate_questions.get(key, False))
        for key in (
            "code_terminal_path_survives",
            "math_terminal_path_survives",
            "same_head_across_refresh",
            "broader_reruns_confirmed",
            "fresh_verified_entrants_preserved_across_refresh",
            "shadow_constraints_preserved_across_refresh",
            "tournament_like_constraints_passed_across_refresh",
            "not_collapsed_back_to_code_specialist_dominance",
        )
    )
    introduced_new_terminal_adapter = len(new_terminal_adapters) > 0
    expanded_terminal_adapter_count = len(candidate_terminals) > len(ceiling_terminals)
    introduced_new_route_pair = len(new_route_pairs) > 0
    expanded_route_pair_count = len(candidate_route_pairs) > len(ceiling_route_pairs)
    route_pair_only_novelty = introduced_new_route_pair and not introduced_new_terminal_adapter

    material_change_earned = (
        candidate_core_constraints_confirmed
        and not same_head_as_ceiling
        and introduced_new_terminal_adapter
        and expanded_terminal_adapter_count
    )

    blockers: List[str] = []
    if same_head_as_ceiling:
        blockers.append("CANDIDATE_REFRESH_IS_SAME_LAB_HEAD_AS_CEILING")
    if not candidate_core_constraints_confirmed:
        blockers.append("CANDIDATE_REFRESH_CORE_CONSTRAINTS_NOT_CONFIRMED")
    if not introduced_new_terminal_adapter:
        blockers.append("NO_NEW_TERMINAL_ADAPTER_BEYOND_CEILING")
    if not expanded_terminal_adapter_count:
        blockers.append("TERMINAL_ADAPTER_COUNT_NOT_EXPANDED")
    if route_pair_only_novelty:
        blockers.append("ROUTE_PAIR_ONLY_NOVELTY_IS_NOT_MATERIAL_CHANGE")

    posture = (
        "READY_FOR_LATER_ROUTER_READINESS_RECONSIDERATION_INPUT_CONSIDERATION"
        if material_change_earned
        else "HOLD_LAB_CEILING__NO_MATERIAL_CHANGE_YET"
    )

    return {
        "schema_id": "kt.lab_readiness_reconsideration_gate_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "claim_boundary": (
            "This packet is lab-only and noncanonical. It does not reopen the counted lane, does not count as R5 evidence, "
            "does not earn router superiority, and cannot unlock R6. Its only job is to say whether a later lab pattern is "
            "materially different enough from the frozen lab ceiling to justify preparing a future router-readiness reconsideration input."
        ),
        "questions": {
            "same_head_as_ceiling": same_head_as_ceiling,
            "candidate_core_constraints_confirmed": candidate_core_constraints_confirmed,
            "introduced_new_terminal_adapter": introduced_new_terminal_adapter,
            "expanded_terminal_adapter_count": expanded_terminal_adapter_count,
            "introduced_new_route_pair": introduced_new_route_pair,
            "expanded_route_pair_count": expanded_route_pair_count,
            "route_pair_only_novelty": route_pair_only_novelty,
            "material_change_earned": material_change_earned,
        },
        "gate_posture": posture,
        "counted_lane_recommendation": "KEEP_COUNTED_LANE_CLOSED",
        "later_reconsideration_gate": (
            "Only when material_change_earned = true may a later router-readiness reconsideration input be prepared. Even then, "
            "counted reopening remains separate and requires its own lawful decision surface."
        ),
        "blockers": blockers,
        "source_packet_refs": {
            "ceiling_packet_ref": ceiling_packet_ref,
            "candidate_refresh_packet_ref": candidate_refresh_packet_ref,
        },
        "ceiling_summary": {
            "ceiling_lab_head": ceiling_head,
            "terminal_adapters": ceiling_terminals,
            "route_pairs": ceiling_route_pairs,
            "terminal_adapter_count": len(ceiling_terminals),
            "route_pair_count": len(ceiling_route_pairs),
        },
        "candidate_summary": {
            "candidate_lab_head": candidate_head,
            "terminal_adapters": candidate_terminals,
            "route_pairs": candidate_route_pairs,
            "terminal_adapter_count": len(candidate_terminals),
            "route_pair_count": len(candidate_route_pairs),
            "new_terminal_adapters": new_terminal_adapters,
            "new_route_pairs": new_route_pairs,
        },
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Gate future router-readiness reconsideration on material lab change beyond the frozen lab ceiling."
    )
    parser.add_argument("--ceiling-packet", required=True)
    parser.add_argument("--candidate-refresh-packet", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    ceiling_ref = str(args.ceiling_packet)
    candidate_ref = str(args.candidate_refresh_packet)
    ceiling_packet = _load_json_dict(_resolve(root, ceiling_ref), name="lab_readiness_ceiling_packet")
    candidate_packet = _load_json_dict(_resolve(root, candidate_ref), name="later_lab_readiness_refresh_packet")

    packet = build_lab_readiness_reconsideration_gate_packet(
        ceiling_packet=ceiling_packet,
        candidate_refresh_packet=candidate_packet,
        ceiling_packet_ref=ceiling_ref,
        candidate_refresh_packet_ref=candidate_ref,
    )
    output_path = _resolve(root, str(args.output))
    write_json_stable(output_path, packet)
    print(json.dumps(packet["questions"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
