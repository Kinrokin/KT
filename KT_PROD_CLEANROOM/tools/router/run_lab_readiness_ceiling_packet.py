from __future__ import annotations

import argparse
import json
from typing import Any, Dict, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.router.run_verified_entrant_lab_scorecard import _load_json_dict, _resolve


def _validate_refresh_packet(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != "kt.later_lab_readiness_refresh_packet.v1":
        raise RuntimeError("FAIL_CLOSED: later lab readiness refresh packet schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: later lab readiness refresh packet mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: later lab readiness refresh packet must be PASS")


def build_lab_readiness_ceiling_packet(
    *,
    later_refresh_packet: Dict[str, Any],
    later_refresh_packet_ref: str,
) -> Dict[str, Any]:
    _validate_refresh_packet(later_refresh_packet)

    questions = later_refresh_packet.get("questions")
    source_heads = later_refresh_packet.get("source_lab_heads")
    if not isinstance(questions, dict) or not isinstance(source_heads, dict):
        raise RuntimeError("FAIL_CLOSED: later lab readiness refresh packet incomplete")

    later_refresh_confirmed = (
        str(later_refresh_packet.get("refresh_posture", "")).strip() == "LATER_LAB_READINESS_REFRESH_CONFIRMED"
    )
    counted_lane_stays_closed = (
        str(later_refresh_packet.get("counted_lane_recommendation", "")).strip() == "KEEP_COUNTED_LANE_CLOSED"
    )
    source_packets_same_lab_head = (
        str(source_heads.get("code_terminal_lab_head", "")).strip()
        == str(source_heads.get("math_terminal_lab_head", "")).strip()
    )
    broader_reruns_confirmed = bool(questions.get("broader_reruns_confirmed", False))
    not_collapsed_back_to_code_specialist_dominance = bool(
        questions.get("not_collapsed_back_to_code_specialist_dominance", False)
    )

    blockers = []
    if not later_refresh_confirmed:
        blockers.append("LATER_REFRESH_NOT_CONFIRMED")
    if not counted_lane_stays_closed:
        blockers.append("COUNTED_LANE_NOT_EXPLICITLY_CLOSED")
    if not source_packets_same_lab_head:
        blockers.append("SOURCE_PACKETS_NOT_SAME_LAB_HEAD")
    if not broader_reruns_confirmed:
        blockers.append("BROADER_RERUNS_NOT_CONFIRMED")
    if not not_collapsed_back_to_code_specialist_dominance:
        blockers.append("TOPOLOGY_COLLAPSE_RISK_STILL_PRESENT")

    ceiling_posture = (
        "LAB_READINESS_CEILING_FROZEN"
        if not blockers
        else "HOLD_LAB_ONLY_PENDING_CEILING_FREEZE_PREREQUISITES"
    )

    return {
        "schema_id": "kt.lab_readiness_ceiling_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "claim_boundary": (
            "This packet freezes the current lab readiness ceiling only. It is lab-only and noncanonical, not tournament "
            "truth, not R5 evidence, does not earn router superiority, does not reopen the counted lane, and cannot unlock "
            "R6, lobe authority, externality, comparative claims, or commercial activation."
        ),
        "questions": {
            "later_refresh_confirmed": later_refresh_confirmed,
            "counted_lane_stays_closed": counted_lane_stays_closed,
            "source_packets_same_lab_head": source_packets_same_lab_head,
            "broader_reruns_confirmed": broader_reruns_confirmed,
            "not_collapsed_back_to_code_specialist_dominance": not_collapsed_back_to_code_specialist_dominance,
        },
        "ceiling_posture": ceiling_posture,
        "counted_lane_recommendation": "KEEP_COUNTED_LANE_CLOSED",
        "lab_recommendation": "PRESERVE_AS_LAB_SIGNAL_ONLY",
        "later_reconsideration_rule": (
            "Only prepare another lab or counted router-readiness reconsideration input if later evidence materially changes the current lab ceiling."
        ),
        "blockers": blockers,
        "source_packet_ref": later_refresh_packet_ref,
        "source_lab_heads": source_heads,
        "source_refresh_summary": {
            "refresh_posture": later_refresh_packet.get("refresh_posture"),
            "terminal_summary": later_refresh_packet.get("terminal_summary"),
            "source_summaries": later_refresh_packet.get("source_summaries"),
        },
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Freeze the current lab readiness ceiling as a lab-only noncanonical packet."
    )
    parser.add_argument("--later-refresh-packet", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    later_ref = str(args.later_refresh_packet)
    later_packet = _load_json_dict(_resolve(root, later_ref), name="later_lab_readiness_refresh_packet")

    packet = build_lab_readiness_ceiling_packet(
        later_refresh_packet=later_packet,
        later_refresh_packet_ref=later_ref,
    )
    output_path = _resolve(root, str(args.output))
    write_json_stable(output_path, packet)
    print(json.dumps(packet["questions"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
