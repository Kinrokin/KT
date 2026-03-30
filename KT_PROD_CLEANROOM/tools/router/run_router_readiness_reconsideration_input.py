from __future__ import annotations

import argparse
import json
from typing import Any, Dict, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.router.run_verified_entrant_lab_scorecard import _load_json_dict, _resolve


def _validate_gate_packet(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != "kt.lab_readiness_reconsideration_gate_packet.v1":
        raise RuntimeError("FAIL_CLOSED: lab readiness reconsideration gate packet schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: lab readiness reconsideration gate packet mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: lab readiness reconsideration gate packet must be PASS")


def _validate_refresh_packet(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != "kt.later_lab_readiness_refresh_packet.v1":
        raise RuntimeError("FAIL_CLOSED: later lab readiness refresh packet schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: later lab readiness refresh packet mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: later lab readiness refresh packet must be PASS")


def build_router_readiness_reconsideration_input(
    *,
    gate_packet: Dict[str, Any],
    candidate_refresh_packet: Dict[str, Any],
    gate_packet_ref: str,
    candidate_refresh_packet_ref: str,
) -> Dict[str, Any]:
    _validate_gate_packet(gate_packet)
    _validate_refresh_packet(candidate_refresh_packet)

    questions = gate_packet.get("questions")
    source_refs = gate_packet.get("source_packet_refs")
    candidate_heads = candidate_refresh_packet.get("source_lab_heads")
    candidate_terminals = candidate_refresh_packet.get("terminal_summary")
    if not isinstance(questions, dict):
        raise RuntimeError("FAIL_CLOSED: gate packet questions missing")
    if not isinstance(source_refs, dict):
        raise RuntimeError("FAIL_CLOSED: gate packet source refs missing")
    if not isinstance(candidate_heads, dict):
        raise RuntimeError("FAIL_CLOSED: candidate refresh source heads missing")
    if not isinstance(candidate_terminals, dict):
        raise RuntimeError("FAIL_CLOSED: candidate refresh terminal summary missing")

    expected_candidate_ref = str(source_refs.get("candidate_refresh_packet_ref", "")).strip().lower()
    provided_candidate_ref = str(candidate_refresh_packet_ref).strip().lower()
    if expected_candidate_ref and expected_candidate_ref != provided_candidate_ref:
        raise RuntimeError("FAIL_CLOSED: candidate refresh packet ref does not match gated source ref")

    if not bool(questions.get("material_change_earned", False)):
        raise RuntimeError("FAIL_CLOSED: reconsideration input cannot be prepared before gate earns material_change_earned = true")

    if bool(questions.get("semantic_bypass_risk", False)):
        raise RuntimeError("FAIL_CLOSED: semantic bypass risk must be false before reconsideration input may be prepared")

    return {
        "schema_id": "kt.router_readiness_reconsideration_input.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "claim_boundary": (
            "This packet is lab-only and noncanonical. It does not reopen the counted lane, does not count as R5 evidence, "
            "does not earn router superiority, and cannot unlock R6. Its only role is to serve as a bounded input to a later "
            "lawful router-readiness reconsideration decision surface after the gate has already earned material_change_earned = true."
        ),
        "gate_requirements_satisfied": {
            "material_change_earned": True,
            "semantic_bypass_risk": False,
            "same_head_as_ceiling": bool(questions.get("same_head_as_ceiling", False)),
            "introduced_new_terminal_adapter": bool(questions.get("introduced_new_terminal_adapter", False)),
            "expanded_terminal_adapter_count": bool(questions.get("expanded_terminal_adapter_count", False)),
            "introduced_new_route_pair": bool(questions.get("introduced_new_route_pair", False)),
            "expanded_route_pair_count": bool(questions.get("expanded_route_pair_count", False)),
        },
        "counted_lane_recommendation": "KEEP_COUNTED_LANE_CLOSED_UNTIL_SEPARATE_LAWFUL_DECISION_SURFACE",
        "source_packet_refs": {
            "gate_packet_ref": gate_packet_ref,
            "candidate_refresh_packet_ref": candidate_refresh_packet_ref,
        },
        "candidate_summary": {
            "candidate_lab_head": str(candidate_heads.get("code_terminal_lab_head", "")).strip(),
            "combined_terminal_adapters": list(candidate_terminals.get("combined_terminal_adapters", [])),
            "combined_terminal_adapter_count": int(candidate_terminals.get("combined_terminal_adapter_count", 0)),
        },
        "next_rule": (
            "A separate lawful decision surface must still decide whether to reconsider router readiness. This packet alone "
            "does not authorize any counted reopening, rerun launch surface, or R6 movement."
        ),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a lab-only router-readiness reconsideration input, but only after the reconsideration gate has already earned material_change_earned = true."
    )
    parser.add_argument("--gate-packet", required=True)
    parser.add_argument("--candidate-refresh-packet", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    gate_ref = str(args.gate_packet)
    candidate_ref = str(args.candidate_refresh_packet)
    gate_packet = _load_json_dict(_resolve(root, gate_ref), name="lab_readiness_reconsideration_gate_packet")
    candidate_packet = _load_json_dict(_resolve(root, candidate_ref), name="later_lab_readiness_refresh_packet")

    packet = build_router_readiness_reconsideration_input(
        gate_packet=gate_packet,
        candidate_refresh_packet=candidate_packet,
        gate_packet_ref=gate_ref,
        candidate_refresh_packet_ref=candidate_ref,
    )
    output_path = _resolve(root, str(args.output))
    write_json_stable(output_path, packet)
    print(json.dumps(packet["gate_requirements_satisfied"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
