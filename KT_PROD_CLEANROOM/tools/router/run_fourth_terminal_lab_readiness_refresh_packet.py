from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.router.run_verified_entrant_lab_scorecard import _load_json_dict, _resolve


_REQUIRED_QUESTIONS = (
    "reproducible_across_reruns",
    "same_head_lab_consistent",
    "shadow_constraints_preserved",
    "survives_fresh_verified_entrants",
    "tournament_like_constraints_passed",
    "second_distinct_topology_visible",
)


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


def _packet_label(ref: str, index: int) -> str:
    stem = Path(str(ref)).stem.strip()
    return stem or f"topology_packet_{index + 1}"


def build_fourth_terminal_lab_readiness_refresh_packet(
    *,
    topology_packets: Sequence[Dict[str, Any]],
    topology_packet_refs: Sequence[str],
) -> Dict[str, Any]:
    if len(topology_packets) < 3:
        raise RuntimeError("FAIL_CLOSED: fourth-terminal refresh requires at least three topology packets")
    if len(topology_packets) != len(topology_packet_refs):
        raise RuntimeError("FAIL_CLOSED: topology packet ref count mismatch")

    combined_terminals: List[str] = []
    combined_route_pairs: List[str] = []
    source_lab_heads: Dict[str, str] = {}
    source_summaries: Dict[str, Any] = {}
    per_packet_questions: Dict[str, Dict[str, bool]] = {}
    blockers: List[str] = []

    reruns_ok = True
    same_head_consistent = True
    shadow_ok = True
    fresh_ok = True
    tournament_ok = True
    topology_ok = True

    for index, (packet, ref) in enumerate(zip(topology_packets, topology_packet_refs)):
        label = _packet_label(ref, index)
        _validate_topology_packet(packet=packet, name=label)

        questions = packet.get("questions")
        summary = packet.get("route_topology_summary")
        if not isinstance(questions, dict) or not isinstance(summary, dict):
            raise RuntimeError(f"FAIL_CLOSED: {label} questions or route summary missing")

        packet_questions = {key: bool(questions.get(key, False)) for key in _REQUIRED_QUESTIONS}
        per_packet_questions[label] = packet_questions
        if not all(packet_questions.values()):
            blockers.append(f"TERMINAL_PATH_NOT_STABLE::{label}")

        reruns_ok = reruns_ok and packet_questions["reproducible_across_reruns"]
        same_head_consistent = same_head_consistent and packet_questions["same_head_lab_consistent"]
        shadow_ok = shadow_ok and packet_questions["shadow_constraints_preserved"]
        fresh_ok = fresh_ok and packet_questions["survives_fresh_verified_entrants"]
        tournament_ok = tournament_ok and packet_questions["tournament_like_constraints_passed"]
        topology_ok = topology_ok and packet_questions["second_distinct_topology_visible"]

        combined_terminals = _ordered_unique(combined_terminals + summary.get("combined_terminal_adapters", []))
        combined_route_pairs = _ordered_unique(combined_route_pairs + summary.get("combined_route_pairs", []))
        source_lab_heads[label] = str(packet.get("lab_head", "")).strip()
        source_summaries[label] = {
            "route_topology_summary": summary,
            "second_topology_summary": packet.get("second_topology_summary"),
        }

    unique_heads = _ordered_unique(source_lab_heads.values())
    same_head_across_refresh = len(unique_heads) == 1
    fourth_terminal_diversity_visible = len(combined_terminals) >= 4

    if not same_head_across_refresh:
        blockers.append("SOURCE_PACKETS_NOT_SAME_LAB_HEAD")
    if not reruns_ok:
        blockers.append("BROADER_RERUNS_NOT_CONFIRMED_ACROSS_ALL_TERMINAL_PATHS")
    if not same_head_consistent:
        blockers.append("SAME_HEAD_CONSISTENCY_NOT_PRESERVED_ACROSS_ALL_TERMINAL_PATHS")
    if not shadow_ok:
        blockers.append("SHADOW_CONSTRAINTS_NOT_PRESERVED_ACROSS_ALL_TERMINAL_PATHS")
    if not fresh_ok:
        blockers.append("FRESH_VERIFIED_ENTRANTS_NOT_PRESERVED_ACROSS_ALL_TERMINAL_PATHS")
    if not tournament_ok:
        blockers.append("TOURNAMENT_LIKE_CONSTRAINTS_NOT_PASSED_ACROSS_ALL_TERMINAL_PATHS")
    if not topology_ok:
        blockers.append("DISTINCT_ROUTE_TOPOLOGY_NOT_VISIBLE_ACROSS_ALL_TERMINAL_PATHS")
    if not fourth_terminal_diversity_visible:
        blockers.append("FOURTH_TERMINAL_DIVERSITY_NOT_VISIBLE")

    posture = (
        "FOURTH_TERMINAL_LAB_READINESS_REFRESH_CONFIRMED"
        if not blockers
        else "HOLD_LAB_ONLY_PENDING_FOURTH_TERMINAL_REFRESH"
    )

    return {
        "schema_id": "kt.fourth_terminal_lab_readiness_refresh_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "claim_boundary": (
            "This packet is lab-only and noncanonical. It checks whether a new same-head router lab slice now supports "
            "a fourth downstream terminal path beyond the preserved three-terminal ceiling, but it is not tournament truth, "
            "not R5 evidence, does not earn router superiority, and cannot unlock R6, lobe authority, externality, "
            "comparative claims, or commercial activation."
        ),
        "questions": {
            "same_head_across_refresh": same_head_across_refresh,
            "broader_reruns_confirmed_across_all_terminal_paths": reruns_ok,
            "same_head_consistency_preserved_across_all_terminal_paths": same_head_consistent,
            "shadow_constraints_preserved_across_all_terminal_paths": shadow_ok,
            "fresh_verified_entrants_preserved_across_all_terminal_paths": fresh_ok,
            "tournament_like_constraints_passed_across_all_terminal_paths": tournament_ok,
            "distinct_route_topology_visible_across_all_terminal_paths": topology_ok,
            "fourth_terminal_diversity_visible": fourth_terminal_diversity_visible,
        },
        "refresh_posture": posture,
        "counted_lane_recommendation": "KEEP_COUNTED_LANE_CLOSED",
        "blockers": blockers,
        "source_packet_refs": list(topology_packet_refs),
        "source_lab_heads": source_lab_heads,
        "source_lab_head": unique_heads[0] if same_head_across_refresh else "",
        "terminal_summary": {
            "combined_terminal_adapters": combined_terminals,
            "combined_terminal_adapter_count": len(combined_terminals),
        },
        "route_summary": {
            "combined_route_pairs": combined_route_pairs,
            "combined_unique_route_pair_count": len(combined_route_pairs),
        },
        "source_summaries": source_summaries,
        "per_packet_questions": per_packet_questions,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a lab-only refresh packet that confirms a fourth downstream terminal path on one same-head router slice."
    )
    parser.add_argument("--topology-packet", action="append", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    packet_refs = [str(item) for item in args.topology_packet]
    packets = [_load_json_dict(_resolve(root, ref), name=f"topology_packet_{index + 1}") for index, ref in enumerate(packet_refs)]

    packet = build_fourth_terminal_lab_readiness_refresh_packet(
        topology_packets=packets,
        topology_packet_refs=packet_refs,
    )
    output_path = _resolve(root, str(args.output))
    write_json_stable(output_path, packet)
    print(json.dumps(packet["questions"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
