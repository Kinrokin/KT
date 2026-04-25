from __future__ import annotations

import argparse
import json
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.router.run_verified_entrant_lab_scorecard import _load_json_dict, _resolve


def _validate_topology_packet(*, packet: Dict[str, Any], name: str) -> None:
    if str(packet.get("schema_id", "")).strip() != "kt.topology_breadth_readiness_packet.v1":
        raise RuntimeError(f"FAIL_CLOSED: {name} schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError(f"FAIL_CLOSED: {name} mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: {name} must be PASS")


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


def build_later_lab_readiness_refresh_packet(
    *,
    code_terminal_packet: Dict[str, Any],
    math_terminal_packet: Dict[str, Any],
    code_terminal_packet_ref: str,
    math_terminal_packet_ref: str,
) -> Dict[str, Any]:
    _validate_topology_packet(packet=code_terminal_packet, name="code_terminal_packet")
    _validate_topology_packet(packet=math_terminal_packet, name="math_terminal_packet")

    code_q = code_terminal_packet.get("questions")
    math_q = math_terminal_packet.get("questions")
    code_summary = code_terminal_packet.get("route_topology_summary")
    math_summary = math_terminal_packet.get("route_topology_summary")
    if not isinstance(code_q, dict) or not isinstance(math_q, dict):
        raise RuntimeError("FAIL_CLOSED: topology packet questions missing")
    if not isinstance(code_summary, dict) or not isinstance(math_summary, dict):
        raise RuntimeError("FAIL_CLOSED: topology packet route summary missing")

    code_terminal_path_survives = (
        bool(code_q.get("reproducible_across_reruns", False))
        and bool(code_q.get("same_head_lab_consistent", False))
        and bool(code_q.get("shadow_constraints_preserved", False))
        and bool(code_q.get("survives_fresh_verified_entrants", False))
        and bool(code_q.get("tournament_like_constraints_passed", False))
        and bool(code_q.get("second_distinct_topology_visible", False))
    )
    math_terminal_path_survives = (
        bool(math_q.get("reproducible_across_reruns", False))
        and bool(math_q.get("same_head_lab_consistent", False))
        and bool(math_q.get("shadow_constraints_preserved", False))
        and bool(math_q.get("survives_fresh_verified_entrants", False))
        and bool(math_q.get("tournament_like_constraints_passed", False))
        and bool(math_q.get("second_distinct_topology_visible", False))
        and bool(math_q.get("downstream_terminal_diversity_earned", False))
        and bool(math_q.get("not_code_specialist_dependence_in_disguise", False))
    )

    same_head_across_refresh = (
        str(code_terminal_packet.get("lab_head", "")).strip()
        == str(math_terminal_packet.get("lab_head", "")).strip()
    )
    broader_reruns_confirmed = bool(code_q.get("reproducible_across_reruns", False)) and bool(
        math_q.get("reproducible_across_reruns", False)
    )
    fresh_verified_entrants_preserved_across_refresh = bool(
        code_q.get("survives_fresh_verified_entrants", False)
    ) and bool(math_q.get("survives_fresh_verified_entrants", False))
    shadow_constraints_preserved_across_refresh = bool(code_q.get("shadow_constraints_preserved", False)) and bool(
        math_q.get("shadow_constraints_preserved", False)
    )
    tournament_like_constraints_passed_across_refresh = bool(
        code_q.get("tournament_like_constraints_passed", False)
    ) and bool(math_q.get("tournament_like_constraints_passed", False))

    code_terminals = _ordered_unique(code_summary.get("combined_terminal_adapters", []))
    math_terminals = _ordered_unique(math_summary.get("combined_terminal_adapters", []))
    combined_terminals = _ordered_unique(code_terminals + math_terminals)
    not_collapsed_back_to_code_specialist_dominance = len(combined_terminals) >= 2 and any(
        terminal != "lobe.code.specialist.v1" for terminal in combined_terminals
    )

    blockers: List[str] = []
    if not code_terminal_path_survives:
        blockers.append("CODE_TERMINAL_PATH_NOT_STABLE")
    if not math_terminal_path_survives:
        blockers.append("MATH_TERMINAL_PATH_NOT_STABLE")
    if not same_head_across_refresh:
        blockers.append("SOURCE_PACKETS_NOT_SAME_LAB_HEAD")
    if not broader_reruns_confirmed:
        blockers.append("BROADER_RERUNS_NOT_CONFIRMED")
    if not fresh_verified_entrants_preserved_across_refresh:
        blockers.append("FRESH_VERIFIED_ENTRANTS_NOT_PRESERVED_ACROSS_REFRESH")
    if not shadow_constraints_preserved_across_refresh:
        blockers.append("SHADOW_CONSTRAINTS_NOT_PRESERVED_ACROSS_REFRESH")
    if not tournament_like_constraints_passed_across_refresh:
        blockers.append("TOURNAMENT_LIKE_CONSTRAINTS_NOT_PASSED_ACROSS_REFRESH")
    if not not_collapsed_back_to_code_specialist_dominance:
        blockers.append("COLLAPSED_BACK_TO_CODE_SPECIALIST_DOMINANCE")

    posture = (
        "LATER_LAB_READINESS_REFRESH_CONFIRMED"
        if not blockers
        else "HOLD_LAB_ONLY_PENDING_BROADER_REFRESH"
    )

    return {
        "schema_id": "kt.later_lab_readiness_refresh_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "claim_boundary": (
            "This packet is lab-only and noncanonical. It refreshes the lab readiness story by checking both the "
            "code-terminal and math-terminal routed patterns on the same lab head, but it is not tournament truth, "
            "not R5 evidence, does not earn router superiority, and cannot unlock R6, lobe authority, externality, "
            "comparative claims, or commercial activation."
        ),
        "questions": {
            "code_terminal_path_survives": code_terminal_path_survives,
            "math_terminal_path_survives": math_terminal_path_survives,
            "same_head_across_refresh": same_head_across_refresh,
            "broader_reruns_confirmed": broader_reruns_confirmed,
            "fresh_verified_entrants_preserved_across_refresh": fresh_verified_entrants_preserved_across_refresh,
            "shadow_constraints_preserved_across_refresh": shadow_constraints_preserved_across_refresh,
            "tournament_like_constraints_passed_across_refresh": tournament_like_constraints_passed_across_refresh,
            "not_collapsed_back_to_code_specialist_dominance": not_collapsed_back_to_code_specialist_dominance,
        },
        "refresh_posture": posture,
        "counted_lane_recommendation": "KEEP_COUNTED_LANE_CLOSED",
        "blockers": blockers,
        "source_packet_refs": {
            "code_terminal_packet_ref": code_terminal_packet_ref,
            "math_terminal_packet_ref": math_terminal_packet_ref,
        },
        "source_lab_heads": {
            "code_terminal_lab_head": str(code_terminal_packet.get("lab_head", "")).strip(),
            "math_terminal_lab_head": str(math_terminal_packet.get("lab_head", "")).strip(),
        },
        "terminal_summary": {
            "code_terminal_adapters": code_terminals,
            "math_terminal_adapters": math_terminals,
            "combined_terminal_adapters": combined_terminals,
            "combined_terminal_adapter_count": len(combined_terminals),
        },
        "source_summaries": {
            "code_route_topology_summary": code_summary,
            "math_route_topology_summary": math_summary,
            "code_second_topology_summary": code_terminal_packet.get("second_topology_summary"),
            "math_second_topology_summary": math_terminal_packet.get("second_topology_summary"),
        },
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a later lab-only readiness refresh packet from code-terminal and math-terminal topology breadth packets."
    )
    parser.add_argument("--code-terminal-packet", required=True)
    parser.add_argument("--math-terminal-packet", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    code_ref = str(args.code_terminal_packet)
    math_ref = str(args.math_terminal_packet)
    code_packet = _load_json_dict(_resolve(root, code_ref), name="code_terminal_packet")
    math_packet = _load_json_dict(_resolve(root, math_ref), name="math_terminal_packet")

    packet = build_later_lab_readiness_refresh_packet(
        code_terminal_packet=code_packet,
        math_terminal_packet=math_packet,
        code_terminal_packet_ref=code_ref,
        math_terminal_packet_ref=math_ref,
    )
    output_path = _resolve(root, str(args.output))
    write_json_stable(output_path, packet)
    print(json.dumps(packet["questions"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
