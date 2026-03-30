from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.router.run_router_readiness_reconsideration_input import (
    LAB_RECONSIDERATION_GATE_PACKET_SCHEMA_ID,
    LATER_LAB_READINESS_REFRESH_SCHEMA_ID,
    RECONSIDERATION_INPUT_SCHEMA_ID,
    SANCTIONED_CONSUMER_VALIDATOR_ENTRYPOINT,
    SANCTIONED_EMITTER_ENTRYPOINT,
    SINGLE_SANCTIONED_PATH_CONTRACT_SCHEMA_ID,
)
from tools.router.run_verified_entrant_lab_scorecard import _load_json_dict, _resolve


def _validate_packet_schema(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != RECONSIDERATION_INPUT_SCHEMA_ID:
        raise RuntimeError("FAIL_CLOSED: router readiness reconsideration input schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: router readiness reconsideration input mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: router readiness reconsideration input must be PASS")


def _validate_gate_packet(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != LAB_RECONSIDERATION_GATE_PACKET_SCHEMA_ID:
        raise RuntimeError("FAIL_CLOSED: lab readiness reconsideration gate packet schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: lab readiness reconsideration gate packet mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: lab readiness reconsideration gate packet must be PASS")


def _validate_candidate_refresh_packet(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != LATER_LAB_READINESS_REFRESH_SCHEMA_ID:
        raise RuntimeError("FAIL_CLOSED: later lab readiness refresh packet schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: later lab readiness refresh packet mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: later lab readiness refresh packet must be PASS")


def _source_ref(packet: Dict[str, Any], key: str) -> str:
    source_refs = packet.get("source_packet_refs")
    if not isinstance(source_refs, dict):
        raise RuntimeError("FAIL_CLOSED: reconsideration input source_packet_refs missing")
    value = str(source_refs.get(key, "")).strip()
    if not value:
        raise RuntimeError(f"FAIL_CLOSED: reconsideration input source ref missing: {key}")
    return value


def _detect_schema_emitters(root: Path) -> List[str]:
    tools_root = root / "KT_PROD_CLEANROOM" / "tools"
    emitters: List[str] = []
    for path in tools_root.rglob("*.py"):
        if path.name == "__init__.py" or "__pycache__" in path.parts:
            continue
        if RECONSIDERATION_INPUT_SCHEMA_ID in path.read_text(encoding="utf-8"):
            emitters.append(path.relative_to(root).as_posix())
    return sorted(set(emitters))


def build_router_readiness_reconsideration_input_validation_receipt(
    *,
    root: Path,
    packet: Dict[str, Any],
    gate_packet: Dict[str, Any],
    candidate_refresh_packet: Dict[str, Any],
    packet_ref: str,
    gate_packet_ref: str,
    candidate_refresh_packet_ref: str,
) -> Dict[str, Any]:
    _validate_packet_schema(packet)
    _validate_gate_packet(gate_packet)
    _validate_candidate_refresh_packet(candidate_refresh_packet)

    packet_contract = packet.get("single_sanctioned_path_contract")
    producer_identity = packet.get("producer_identity")
    packet_requirements = packet.get("gate_requirements_satisfied")
    candidate_heads = candidate_refresh_packet.get("source_lab_heads")
    candidate_terminals = candidate_refresh_packet.get("terminal_summary")
    gate_questions = gate_packet.get("questions")
    gate_source_refs = gate_packet.get("source_packet_refs")
    if not isinstance(packet_contract, dict):
        raise RuntimeError("FAIL_CLOSED: reconsideration input contract block missing")
    if not isinstance(producer_identity, dict):
        raise RuntimeError("FAIL_CLOSED: reconsideration input producer identity missing")
    if not isinstance(packet_requirements, dict):
        raise RuntimeError("FAIL_CLOSED: reconsideration input gate requirements missing")
    if not isinstance(candidate_heads, dict):
        raise RuntimeError("FAIL_CLOSED: candidate refresh source_lab_heads missing")
    if not isinstance(candidate_terminals, dict):
        raise RuntimeError("FAIL_CLOSED: candidate refresh terminal_summary missing")
    if not isinstance(gate_questions, dict):
        raise RuntimeError("FAIL_CLOSED: gate packet questions missing")
    if not isinstance(gate_source_refs, dict):
        raise RuntimeError("FAIL_CLOSED: gate packet source refs missing")

    detected_emitters = _detect_schema_emitters(root)
    packet_gate_ref = _source_ref(packet, "gate_packet_ref")
    packet_candidate_ref = _source_ref(packet, "candidate_refresh_packet_ref")
    candidate_adapters = list(candidate_terminals.get("combined_terminal_adapters", []))
    candidate_adapter_count = int(candidate_terminals.get("combined_terminal_adapter_count", 0))

    checks = [
        {
            "check_id": "packet_is_lab_only_pass_and_fail_closed_by_scope",
            "pass": str(packet.get("counted_lane_recommendation", "")).strip()
            == "KEEP_COUNTED_LANE_CLOSED_UNTIL_SEPARATE_LAWFUL_DECISION_SURFACE"
            and "does not reopen the counted lane" in str(packet.get("claim_boundary", "")).lower(),
        },
        {
            "check_id": "single_sanctioned_path_contract_matches_expected_pair",
            "pass": str(packet_contract.get("schema_id", "")).strip() == SINGLE_SANCTIONED_PATH_CONTRACT_SCHEMA_ID
            and str(packet_contract.get("sanctioned_emitter_entrypoint", "")).strip() == SANCTIONED_EMITTER_ENTRYPOINT
            and str(packet_contract.get("sanctioned_consumer_validator_entrypoint", "")).strip()
            == SANCTIONED_CONSUMER_VALIDATOR_ENTRYPOINT
            and str(packet_contract.get("required_gate_packet_schema_id", "")).strip()
            == LAB_RECONSIDERATION_GATE_PACKET_SCHEMA_ID
            and str(packet_contract.get("required_candidate_refresh_packet_schema_id", "")).strip()
            == LATER_LAB_READINESS_REFRESH_SCHEMA_ID,
        },
        {
            "check_id": "producer_identity_matches_sanctioned_emitter",
            "pass": str(producer_identity.get("prepared_by_entrypoint", "")).strip() == SANCTIONED_EMITTER_ENTRYPOINT
            and str(producer_identity.get("schema_emitted", "")).strip() == RECONSIDERATION_INPUT_SCHEMA_ID,
        },
        {
            "check_id": "packet_refs_match_loaded_gate_and_candidate_sources",
            "pass": packet_gate_ref == str(gate_packet_ref).strip()
            and packet_candidate_ref == str(candidate_refresh_packet_ref).strip()
            and str(gate_source_refs.get("candidate_refresh_packet_ref", "")).strip() == str(candidate_refresh_packet_ref).strip(),
        },
        {
            "check_id": "gate_packet_clean_and_material_change_earned",
            "pass": bool(gate_questions.get("material_change_earned", False))
            and not bool(gate_questions.get("semantic_bypass_risk", False)),
        },
        {
            "check_id": "packet_gate_requirements_match_clean_gate_state",
            "pass": packet_requirements.get("material_change_earned") is True
            and packet_requirements.get("semantic_bypass_risk") is False,
        },
        {
            "check_id": "candidate_summary_matches_candidate_refresh_packet",
            "pass": str(packet.get("candidate_summary", {}).get("candidate_lab_head", "")).strip()
            == str(candidate_heads.get("code_terminal_lab_head", "")).strip()
            and list(packet.get("candidate_summary", {}).get("combined_terminal_adapters", [])) == candidate_adapters
            and int(packet.get("candidate_summary", {}).get("combined_terminal_adapter_count", 0)) == candidate_adapter_count,
        },
        {
            "check_id": "single_sanctioned_emitter_uniqueness_holds_in_repo_tools",
            "pass": detected_emitters == [SANCTIONED_EMITTER_ENTRYPOINT],
        },
        {
            "check_id": "next_rule_remains_non_authorizing",
            "pass": "does not authorize any counted reopening" in str(packet.get("next_rule", "")).lower(),
        },
    ]

    status = "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL"
    return {
        "schema_id": "kt.router_readiness_reconsideration_input_validation_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": status,
        "subject_packet_ref": packet_ref,
        "source_packet_refs": {
            "gate_packet_ref": gate_packet_ref,
            "candidate_refresh_packet_ref": candidate_refresh_packet_ref,
        },
        "sanctioned_path_contract": {
            "sanctioned_emitter_entrypoint": SANCTIONED_EMITTER_ENTRYPOINT,
            "sanctioned_consumer_validator_entrypoint": SANCTIONED_CONSUMER_VALIDATOR_ENTRYPOINT,
        },
        "detected_schema_emitters": detected_emitters,
        "checks": checks,
        "claim_boundary": (
            "This receipt validates only the lab-only router-readiness reconsideration input contract and its single sanctioned "
            "emitter/consumer path. It does not reopen the counted lane, does not count as R5 evidence, and cannot unlock R6."
        ),
        "next_rule": (
            "Even when this validation receipt passes, any future router-readiness reconsideration still remains lab-only until a "
            "separate lawful decision surface decides otherwise."
        ),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate a lab-only router-readiness reconsideration input against its sanctioned emitter/consumer contract."
    )
    parser.add_argument("--input", required=True)
    parser.add_argument("--gate-packet")
    parser.add_argument("--candidate-refresh-packet")
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    packet_ref = str(args.input)
    packet = _load_json_dict(_resolve(root, packet_ref), name="router_readiness_reconsideration_input")
    gate_ref = str(args.gate_packet or _source_ref(packet, "gate_packet_ref"))
    candidate_ref = str(args.candidate_refresh_packet or _source_ref(packet, "candidate_refresh_packet_ref"))
    gate_packet = _load_json_dict(_resolve(root, gate_ref), name="lab_readiness_reconsideration_gate_packet")
    candidate_packet = _load_json_dict(_resolve(root, candidate_ref), name="later_lab_readiness_refresh_packet")

    receipt = build_router_readiness_reconsideration_input_validation_receipt(
        root=root,
        packet=packet,
        gate_packet=gate_packet,
        candidate_refresh_packet=candidate_packet,
        packet_ref=packet_ref,
        gate_packet_ref=gate_ref,
        candidate_refresh_packet_ref=candidate_ref,
    )
    output_path = _resolve(root, str(args.output))
    write_json_stable(output_path, receipt)
    summary = {
        "status": receipt["status"],
        "detected_schema_emitter_count": len(receipt["detected_schema_emitters"]),
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
