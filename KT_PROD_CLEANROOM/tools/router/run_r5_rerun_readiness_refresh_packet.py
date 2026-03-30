from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.router.run_verified_entrant_lab_scorecard import _load_json_dict, _resolve


def _validate_lab_packet(*, packet: Dict[str, Any], schema_id: str, name: str) -> None:
    if str(packet.get("schema_id", "")).strip() != schema_id:
        raise RuntimeError(f"FAIL_CLOSED: {name} schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError(f"FAIL_CLOSED: {name} mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: {name} must be PASS")


def build_r5_rerun_readiness_refresh_packet(
    *,
    base_readiness_packet: Dict[str, Any],
    role_separated_survival_packet: Dict[str, Any],
    base_readiness_packet_ref: str,
    role_separated_survival_packet_ref: str,
) -> Dict[str, Any]:
    _validate_lab_packet(
        packet=base_readiness_packet,
        schema_id="kt.r5_rerun_readiness_packet.v1",
        name="base_readiness_packet",
    )
    _validate_lab_packet(
        packet=role_separated_survival_packet,
        schema_id="kt.role_separated_router_survival_packet.v1",
        name="role_separated_survival_packet",
    )

    base_questions = base_readiness_packet.get("questions")
    role_questions = role_separated_survival_packet.get("questions")
    if not isinstance(base_questions, dict) or not isinstance(role_questions, dict):
        raise RuntimeError("FAIL_CLOSED: source packet questions missing")

    base_readiness_clean = (
        str(base_readiness_packet.get("readiness_posture", "")).strip()
        == "READY_FOR_COUNTED_R5_RERUN_CONSIDERATION"
    )
    role_separated_survival_confirmed = (
        str(role_separated_survival_packet.get("posture", "")).strip()
        == "LAB_ROLE_SEPARATED_SURVIVAL_CONFIRMED"
    )
    source_packets_individually_same_head_consistent = bool(base_questions.get("same_head_lab_consistent", False)) and bool(
        role_questions.get("same_head_lab_consistent", False)
    )
    source_packets_same_lab_head = (
        str(base_readiness_packet.get("lab_head", "")).strip()
        == str(role_separated_survival_packet.get("lab_head", "")).strip()
    )
    shadow_constraints_preserved = bool(base_questions.get("shadow_constraints_preserved", False)) and bool(
        role_questions.get("shadow_constraints_preserved", False)
    )
    survives_fresh_verified_entrants = bool(base_questions.get("survives_fresh_verified_entrants", False)) and bool(
        role_questions.get("survives_fresh_verified_entrants", False)
    )
    role_separated_tournament_like_constraints_passed = bool(
        role_questions.get("tournament_like_constraints_passed", False)
    )

    blockers = []
    if not base_readiness_clean:
        blockers.append("BASE_R5_LAB_READINESS_NOT_CLEAN")
    if not role_separated_survival_confirmed:
        blockers.append("ROLE_SEPARATED_SURVIVAL_NOT_CONFIRMED")
    if not source_packets_individually_same_head_consistent:
        blockers.append("SOURCE_PACKET_SAME_HEAD_CONSISTENCY_NOT_CONFIRMED")
    if not shadow_constraints_preserved:
        blockers.append("LAB_SHADOW_CONSTRAINTS_NOT_PRESERVED_ACROSS_REFRESH")
    if not survives_fresh_verified_entrants:
        blockers.append("FRESH_VERIFIED_ENTRANT_SURVIVAL_NOT_CONFIRMED_ACROSS_REFRESH")
    if not role_separated_tournament_like_constraints_passed:
        blockers.append("ROLE_SEPARATED_TOURNAMENT_LIKE_THRESHOLD_NOT_EARNED")

    readiness_posture = (
        "READY_FOR_SEPARATE_COUNTED_R5_RERUN_LAUNCH_SURFACE_CONSIDERATION"
        if not blockers
        else "HOLD_LAB_ONLY_PENDING_ADDITIONAL_CONFIRMATION"
    )

    return {
        "schema_id": "kt.r5_rerun_readiness_refresh_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "claim_boundary": (
            "This refreshed packet is lab-only and noncanonical. It merges a clean R5 lab-readiness packet "
            "with a clean role-separated survival packet to decide whether a separate counted same-head R5 rerun "
            "launch surface can be considered, but it is not R5 evidence, does not earn router superiority, and "
            "cannot unlock R6, lobe authority, externality, comparative claims, or commercial activation."
        ),
        "questions": {
            "base_readiness_clean": base_readiness_clean,
            "role_separated_survival_confirmed": role_separated_survival_confirmed,
            "source_packets_individually_same_head_consistent": source_packets_individually_same_head_consistent,
            "source_packets_same_lab_head": source_packets_same_lab_head,
            "shadow_constraints_preserved": shadow_constraints_preserved,
            "survives_fresh_verified_entrants": survives_fresh_verified_entrants,
            "role_separated_tournament_like_constraints_passed": role_separated_tournament_like_constraints_passed,
        },
        "readiness_posture": readiness_posture,
        "counted_lane_recommendation": (
            "SEPARATE_COUNTED_R5_RERUN_LAUNCH_SURFACE_CAN_BE_CONSIDERED"
            if not blockers
            else "DO_NOT_OPEN_COUNTED_R5_RERUN_LAUNCH_SURFACE_YET"
        ),
        "blockers": blockers,
        "source_packet_refs": {
            "base_readiness_packet_ref": base_readiness_packet_ref,
            "role_separated_survival_packet_ref": role_separated_survival_packet_ref,
        },
        "source_lab_heads": {
            "base_readiness_lab_head": str(base_readiness_packet.get("lab_head", "")).strip(),
            "role_separated_lab_head": str(role_separated_survival_packet.get("lab_head", "")).strip(),
        },
        "source_readiness_summaries": {
            "base_signal": base_readiness_packet.get("lab_signal_summaries"),
            "role_separated_signal": role_separated_survival_packet.get("role_separated_summary"),
            "role_separated_tournament_like_assessment": role_separated_survival_packet.get("tournament_like_assessment"),
        },
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a refreshed lab-only R5 rerun readiness packet from clean source packets."
    )
    parser.add_argument("--base-readiness-packet", required=True)
    parser.add_argument("--role-separated-survival-packet", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    base_ref = str(args.base_readiness_packet)
    role_ref = str(args.role_separated_survival_packet)
    base_packet = _load_json_dict(_resolve(root, base_ref), name="base_readiness_packet")
    role_packet = _load_json_dict(_resolve(root, role_ref), name="role_separated_survival_packet")

    packet = build_r5_rerun_readiness_refresh_packet(
        base_readiness_packet=base_packet,
        role_separated_survival_packet=role_packet,
        base_readiness_packet_ref=base_ref,
        role_separated_survival_packet_ref=role_ref,
    )
    output_path = _resolve(root, str(args.output))
    write_json_stable(output_path, packet)
    print(json.dumps(packet["questions"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
