from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.router.run_verified_entrant_lab_scorecard import _load_json_dict, _resolve

RECONSIDERATION_INPUT_SCHEMA_ID = "kt.router_readiness_reconsideration_input.v1"
LAB_RECONSIDERATION_GATE_PACKET_SCHEMA_ID = "kt.lab_readiness_reconsideration_gate_packet.v1"
LATER_LAB_READINESS_REFRESH_SCHEMA_ID = "kt.later_lab_readiness_refresh_packet.v1"
SINGLE_SANCTIONED_PATH_CONTRACT_SCHEMA_ID = "kt.router_readiness_reconsideration_input.single_sanctioned_path_contract.v1"
SINGLE_PATH_ENFORCEMENT_RECEIPT_SCHEMA_ID = "kt.router_readiness_reconsideration_input_single_path_enforcement_receipt.v1"
HOLD_STATE_BASIS_VALIDATION_RECEIPT_SCHEMA_ID = "kt.hold_state_surface_basis_validation_receipt.v1"
SANCTIONED_EMITTER_ENTRYPOINT = "KT_PROD_CLEANROOM/tools/router/run_router_readiness_reconsideration_input.py"
SANCTIONED_CONSUMER_VALIDATOR_ENTRYPOINT = (
    "KT_PROD_CLEANROOM/tools/operator/router_readiness_reconsideration_input_validate.py"
)
SANCTIONED_SCHEMA_TOUCHERS = sorted(
    [
        SANCTIONED_CONSUMER_VALIDATOR_ENTRYPOINT,
        SANCTIONED_EMITTER_ENTRYPOINT,
    ]
)


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _validate_gate_packet(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != LAB_RECONSIDERATION_GATE_PACKET_SCHEMA_ID:
        raise RuntimeError("FAIL_CLOSED: lab readiness reconsideration gate packet schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: lab readiness reconsideration gate packet mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: lab readiness reconsideration gate packet must be PASS")


def _validate_refresh_packet(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != LATER_LAB_READINESS_REFRESH_SCHEMA_ID:
        raise RuntimeError("FAIL_CLOSED: later lab readiness refresh packet schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: later lab readiness refresh packet mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: later lab readiness refresh packet must be PASS")


def _validate_single_path_guard_receipt(
    *,
    packet: Dict[str, Any],
    current_git_head: str,
    candidate_refresh_packet: Dict[str, Any],
) -> Dict[str, Any]:
    if str(packet.get("schema_id", "")).strip() != SINGLE_PATH_ENFORCEMENT_RECEIPT_SCHEMA_ID:
        raise RuntimeError("FAIL_CLOSED: single-path guard receipt schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: single-path guard receipt mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: single-path guard receipt must be PASS")

    sanctioned_paths = packet.get("sanctioned_paths")
    if not isinstance(sanctioned_paths, dict):
        raise RuntimeError("FAIL_CLOSED: single-path guard sanctioned_paths missing")
    if str(sanctioned_paths.get("emitter", "")).strip() != SANCTIONED_EMITTER_ENTRYPOINT:
        raise RuntimeError("FAIL_CLOSED: single-path guard emitter mismatch")
    if str(sanctioned_paths.get("consumer_validator", "")).strip() != SANCTIONED_CONSUMER_VALIDATOR_ENTRYPOINT:
        raise RuntimeError("FAIL_CLOSED: single-path guard consumer validator mismatch")

    detected_emitters = list(packet.get("detected_schema_emitters", []))
    detected_touchers = list(packet.get("detected_schema_touchers", []))
    if detected_emitters != [SANCTIONED_EMITTER_ENTRYPOINT]:
        raise RuntimeError("FAIL_CLOSED: single-path guard emitter set mismatch")
    if detected_touchers != SANCTIONED_SCHEMA_TOUCHERS:
        raise RuntimeError("FAIL_CLOSED: single-path guard toucher set mismatch")

    guard_head = str(packet.get("current_git_head", "")).strip()
    if not guard_head:
        raise RuntimeError("FAIL_CLOSED: single-path guard current_git_head missing")
    if guard_head != str(current_git_head).strip():
        raise RuntimeError("FAIL_CLOSED: single-path guard is not fresh on current candidate head")

    source_heads = candidate_refresh_packet.get("source_lab_heads")
    if not isinstance(source_heads, dict):
        raise RuntimeError("FAIL_CLOSED: candidate refresh source heads missing")
    candidate_heads = {
        str(source_heads.get("code_terminal_lab_head", "")).strip(),
        str(source_heads.get("math_terminal_lab_head", "")).strip(),
    }
    candidate_heads = {item for item in candidate_heads if item}
    if not candidate_heads:
        raise RuntimeError("FAIL_CLOSED: candidate refresh source heads empty")
    if candidate_heads != {guard_head}:
        raise RuntimeError("FAIL_CLOSED: single-path guard head does not match candidate refresh head")
    return {
        "guard_head": guard_head,
        "detected_schema_emitter_count": len(detected_emitters),
        "detected_schema_toucher_count": len(detected_touchers),
    }


def _validate_hold_state_basis_receipt(
    *,
    packet: Dict[str, Any],
    current_git_head: str,
) -> Dict[str, Any]:
    if str(packet.get("schema_id", "")).strip() != HOLD_STATE_BASIS_VALIDATION_RECEIPT_SCHEMA_ID:
        raise RuntimeError("FAIL_CLOSED: hold-state basis receipt schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: hold-state basis receipt mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: hold-state basis receipt must be PASS")
    if str(packet.get("head_alignment_posture", "")).strip() != "PRE_SEAL_HOLD_STATE_BASIS_CONFIRMED":
        raise RuntimeError("FAIL_CLOSED: hold-state basis posture mismatch")

    actual_repo_head = str(packet.get("actual_repo_head", "")).strip()
    tracked_basis_head = str(packet.get("tracked_surface_basis_head", "")).strip()
    if not actual_repo_head:
        raise RuntimeError("FAIL_CLOSED: hold-state basis receipt actual_repo_head missing")
    if not tracked_basis_head:
        raise RuntimeError("FAIL_CLOSED: hold-state basis receipt tracked_surface_basis_head missing")
    if actual_repo_head != str(current_git_head).strip():
        raise RuntimeError("FAIL_CLOSED: hold-state basis receipt is not fresh on current candidate head")
    if tracked_basis_head == actual_repo_head:
        raise RuntimeError("FAIL_CLOSED: hold-state basis receipt cannot collapse into same-head authority")
    if "pre-seal basis only" not in str(packet.get("resolution_rule", "")).lower():
        raise RuntimeError("FAIL_CLOSED: hold-state basis resolution rule missing preserved-basis boundary")

    return {
        "actual_repo_head": actual_repo_head,
        "tracked_surface_basis_head": tracked_basis_head,
    }


def build_router_readiness_reconsideration_input(
    *,
    current_git_head: str,
    gate_packet: Dict[str, Any],
    candidate_refresh_packet: Dict[str, Any],
    single_path_guard_receipt: Dict[str, Any],
    hold_state_basis_receipt: Dict[str, Any],
    gate_packet_ref: str,
    candidate_refresh_packet_ref: str,
    single_path_guard_receipt_ref: str,
    hold_state_basis_receipt_ref: str,
) -> Dict[str, Any]:
    _validate_gate_packet(gate_packet)
    _validate_refresh_packet(candidate_refresh_packet)
    single_path_guard_summary = _validate_single_path_guard_receipt(
        packet=single_path_guard_receipt,
        current_git_head=current_git_head,
        candidate_refresh_packet=candidate_refresh_packet,
    )
    hold_state_basis_summary = _validate_hold_state_basis_receipt(
        packet=hold_state_basis_receipt,
        current_git_head=current_git_head,
    )

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
        "schema_id": RECONSIDERATION_INPUT_SCHEMA_ID,
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "claim_boundary": (
            "This packet is lab-only and noncanonical. It does not reopen the counted lane, does not count as R5 evidence, "
            "does not earn router superiority, and cannot unlock R6. Its only role is to serve as a bounded input to a later "
            "lawful router-readiness reconsideration decision surface after the gate has already earned material_change_earned = true."
        ),
        "producer_identity": {
            "prepared_by_entrypoint": SANCTIONED_EMITTER_ENTRYPOINT,
            "prepared_from_module": "tools.router.run_router_readiness_reconsideration_input",
            "schema_emitted": RECONSIDERATION_INPUT_SCHEMA_ID,
        },
        "single_sanctioned_path_contract": {
            "schema_id": SINGLE_SANCTIONED_PATH_CONTRACT_SCHEMA_ID,
            "sanctioned_emitter_entrypoint": SANCTIONED_EMITTER_ENTRYPOINT,
            "sanctioned_consumer_validator_entrypoint": SANCTIONED_CONSUMER_VALIDATOR_ENTRYPOINT,
            "required_single_path_guard_receipt_schema_id": SINGLE_PATH_ENFORCEMENT_RECEIPT_SCHEMA_ID,
            "required_hold_state_basis_receipt_schema_id": HOLD_STATE_BASIS_VALIDATION_RECEIPT_SCHEMA_ID,
            "required_gate_packet_schema_id": LAB_RECONSIDERATION_GATE_PACKET_SCHEMA_ID,
            "required_candidate_refresh_packet_schema_id": LATER_LAB_READINESS_REFRESH_SCHEMA_ID,
            "consumer_contract_rule": (
                "Any consumer must reject this packet unless it came through the sanctioned emitter path and is validated "
                "through the sanctioned operator validator named in this contract."
            ),
            "same_head_guard_rule": (
                "A fresh single-path enforcement receipt must be re-emitted on the actual candidate head before any "
                "router-readiness reconsideration input may be prepared or consumed."
            ),
            "preseal_basis_rule": (
                "The hold-state basis receipt may only confirm preserved pre-seal basis. It may never be treated as "
                "same-head authority or as a substitute for fresh guard evidence on the actual candidate head."
            ),
        },
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
            "single_path_guard_receipt_ref": single_path_guard_receipt_ref,
            "hold_state_basis_receipt_ref": hold_state_basis_receipt_ref,
        },
        "single_path_guard_summary": single_path_guard_summary,
        "hold_state_basis_summary": hold_state_basis_summary,
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
    parser.add_argument("--single-path-guard-receipt", required=True)
    parser.add_argument("--hold-state-basis-receipt", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    current_head = _git_head(root)
    gate_ref = str(args.gate_packet)
    candidate_ref = str(args.candidate_refresh_packet)
    guard_ref = str(args.single_path_guard_receipt)
    hold_state_basis_ref = str(args.hold_state_basis_receipt)
    gate_packet = _load_json_dict(_resolve(root, gate_ref), name="lab_readiness_reconsideration_gate_packet")
    candidate_packet = _load_json_dict(_resolve(root, candidate_ref), name="later_lab_readiness_refresh_packet")
    guard_packet = _load_json_dict(_resolve(root, guard_ref), name="router_readiness_reconsideration_single_path_enforcement_receipt")
    hold_state_basis_packet = _load_json_dict(
        _resolve(root, hold_state_basis_ref),
        name="hold_state_surface_basis_validation_receipt",
    )

    packet = build_router_readiness_reconsideration_input(
        current_git_head=current_head,
        gate_packet=gate_packet,
        candidate_refresh_packet=candidate_packet,
        single_path_guard_receipt=guard_packet,
        hold_state_basis_receipt=hold_state_basis_packet,
        gate_packet_ref=gate_ref,
        candidate_refresh_packet_ref=candidate_ref,
        single_path_guard_receipt_ref=guard_ref,
        hold_state_basis_receipt_ref=hold_state_basis_ref,
    )
    output_path = _resolve(root, str(args.output))
    write_json_stable(output_path, packet)
    print(json.dumps(packet["gate_requirements_satisfied"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
