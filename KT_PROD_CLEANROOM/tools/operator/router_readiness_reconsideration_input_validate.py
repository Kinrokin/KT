from __future__ import annotations

import argparse
import ast
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.router.run_router_readiness_reconsideration_input import (
    ALLOWED_CANDIDATE_REFRESH_PACKET_SCHEMA_IDS,
    ALLOWED_GATE_PACKET_SCHEMA_IDS,
    FOURTH_TERMINAL_LAB_READINESS_REFRESH_SCHEMA_ID,
    HOLD_STATE_BASIS_VALIDATION_RECEIPT_SCHEMA_ID,
    LAB_RECONSIDERATION_GATE_PACKET_SCHEMA_ID,
    LATER_LAB_READINESS_REFRESH_SCHEMA_ID,
    POST_THIRD_RERUN_MATERIAL_CHANGE_GATE_PACKET_SCHEMA_ID,
    RECONSIDERATION_INPUT_SCHEMA_ID,
    SANCTIONED_CONSUMER_VALIDATOR_ENTRYPOINT,
    SANCTIONED_EMITTER_ENTRYPOINT,
    SINGLE_SANCTIONED_PATH_CONTRACT_SCHEMA_ID,
    _candidate_primary_head,
    _candidate_refresh_heads,
    _candidate_refresh_packet_schema_id,
    _gate_packet_schema_id,
)
from tools.router.run_verified_entrant_lab_scorecard import _load_json_dict, _resolve


SANCTIONED_SCHEMA_TOUCHERS = sorted(
    [
    SANCTIONED_EMITTER_ENTRYPOINT,
    SANCTIONED_CONSUMER_VALIDATOR_ENTRYPOINT,
    ]
)
SINGLE_PATH_ENFORCEMENT_RECEIPT_SCHEMA_ID = "kt.router_readiness_reconsideration_input_single_path_enforcement_receipt.v1"
RECONSIDERATION_ADJUDICATION_RECEIPT_SCHEMA_ID = "kt.router_readiness_reconsideration_adjudication_receipt.v1"
FROZEN_INTER_GATE_STATE = "GATE_D_LAB_READINESS_RECONSIDERATION_GATE_FROZEN__COUNTED_LANE_CLOSED"
FROZEN_BLOCKING_STATE = "LAB_READINESS_RECONSIDERATION_GATE_FROZEN__COUNTED_LANE_CLOSED__R6_STILL_BLOCKED_PENDING_EARNED_SUPERIORITY"
FROZEN_NEXT_LAWFUL_MOVE = "HOLD_LAB_READINESS_CEILING_AND_RECONSIDERATION_GATE__COUNTED_LANE_CLOSED__R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF"
NEXT_IN_ORDER_ID = "B04_R6_LEARNED_ROUTER_AUTHORIZATION"
LEGACY_ADJUDICATION_POSTURE = "READY_FOR_SEPARATE_COUNTED_R5_RERUN_LAUNCH_SURFACE_CONSIDERATION"
LEGACY_ADJUDICATION_NEXT_MOVE = "CONSIDER_B04_R5_THIRD_SAME_HEAD_RERUN_LAUNCH_SURFACE_ONLY"
POST_THIRD_RERUN_ADJUDICATION_POSTURE = "READY_FOR_SEPARATE_COUNTED_R5_FOURTH_SAME_HEAD_RERUN_LAUNCH_SURFACE_CONSIDERATION"
POST_THIRD_RERUN_ADJUDICATION_NEXT_MOVE = "CONSIDER_B04_R5_FOURTH_SAME_HEAD_RERUN_LAUNCH_SURFACE_ONLY"
ADJUDICATION_POSTURE = LEGACY_ADJUDICATION_POSTURE
ADJUDICATION_NEXT_MOVE = LEGACY_ADJUDICATION_NEXT_MOVE


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _validate_packet_schema(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != RECONSIDERATION_INPUT_SCHEMA_ID:
        raise RuntimeError("FAIL_CLOSED: router readiness reconsideration input schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: router readiness reconsideration input mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: router readiness reconsideration input must be PASS")


def _validate_gate_packet(packet: Dict[str, Any]) -> None:
    if _gate_packet_schema_id(packet) not in ALLOWED_GATE_PACKET_SCHEMA_IDS:
        raise RuntimeError("FAIL_CLOSED: lab readiness reconsideration gate packet schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: lab readiness reconsideration gate packet mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: lab readiness reconsideration gate packet must be PASS")


def _validate_candidate_refresh_packet(packet: Dict[str, Any]) -> None:
    if _candidate_refresh_packet_schema_id(packet) not in ALLOWED_CANDIDATE_REFRESH_PACKET_SCHEMA_IDS:
        raise RuntimeError("FAIL_CLOSED: later lab readiness refresh packet schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: later lab readiness refresh packet mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: later lab readiness refresh packet must be PASS")


def _validate_single_path_guard_receipt(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != SINGLE_PATH_ENFORCEMENT_RECEIPT_SCHEMA_ID:
        raise RuntimeError("FAIL_CLOSED: single-path guard receipt schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: single-path guard receipt mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: single-path guard receipt must be PASS")


def _validate_hold_state_basis_receipt(packet: Dict[str, Any], *, current_head: str) -> None:
    if str(packet.get("schema_id", "")).strip() != HOLD_STATE_BASIS_VALIDATION_RECEIPT_SCHEMA_ID:
        raise RuntimeError("FAIL_CLOSED: hold-state basis receipt schema mismatch")
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: hold-state basis receipt mode mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: hold-state basis receipt must be PASS")
    if str(packet.get("head_alignment_posture", "")).strip() != "PRE_SEAL_HOLD_STATE_BASIS_CONFIRMED":
        raise RuntimeError("FAIL_CLOSED: hold-state basis posture mismatch")
    if str(packet.get("actual_repo_head", "")).strip() != str(current_head).strip():
        raise RuntimeError("FAIL_CLOSED: hold-state basis receipt is not fresh on current head")
    if str(packet.get("tracked_surface_basis_head", "")).strip() == str(current_head).strip():
        raise RuntimeError("FAIL_CLOSED: hold-state basis receipt cannot act as same-head authority")


def _validate_current_state_overlay_for_reconsideration_adjudication(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != "kt.current_campaign_state_overlay.v1":
        raise RuntimeError("FAIL_CLOSED: current campaign state overlay schema mismatch")
    if str(packet.get("next_counted_workstream_id", "")).strip() != NEXT_IN_ORDER_ID:
        raise RuntimeError("FAIL_CLOSED: current campaign state overlay next counted workstream mismatch")
    if bool(packet.get("repo_state_executable_now", True)):
        raise RuntimeError("FAIL_CLOSED: current campaign state unexpectedly executable")
    lawful_standing = packet.get("current_lawful_gate_standing")
    if not isinstance(lawful_standing, dict):
        raise RuntimeError("FAIL_CLOSED: current campaign lawful standing missing")
    if str(lawful_standing.get("inter_gate_state", "")).strip() != FROZEN_INTER_GATE_STATE:
        raise RuntimeError("FAIL_CLOSED: current campaign state is not the frozen reconsideration posture")


def _validate_next_counted_workstream_contract_for_reconsideration_adjudication(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != "kt.next_counted_workstream_contract.v1":
        raise RuntimeError("FAIL_CLOSED: next counted workstream contract schema mismatch")
    if str(packet.get("exact_next_counted_workstream_id", "")).strip() != NEXT_IN_ORDER_ID:
        raise RuntimeError("FAIL_CLOSED: next counted workstream contract next step mismatch")
    if bool(packet.get("repo_state_executable_now", True)):
        raise RuntimeError("FAIL_CLOSED: next counted workstream contract unexpectedly executable")


def _validate_resume_blockers_for_reconsideration_adjudication(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != "kt.resume_blockers_receipt.v1":
        raise RuntimeError("FAIL_CLOSED: resume blockers receipt schema mismatch")
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: resume blockers receipt must be PASS")
    if str(packet.get("blocking_state", "")).strip() != FROZEN_BLOCKING_STATE:
        raise RuntimeError("FAIL_CLOSED: resume blockers receipt is not at the frozen reconsideration hold")
    if bool(packet.get("repo_state_executable_now", True)):
        raise RuntimeError("FAIL_CLOSED: resume blockers receipt unexpectedly executable")


def _validate_reanchor_for_reconsideration_adjudication(packet: Dict[str, Any]) -> None:
    if str(packet.get("schema_id", "")).strip() != "kt.gate_d.decision_reanchor_packet.v1":
        raise RuntimeError("FAIL_CLOSED: gate D decision reanchor packet schema mismatch")
    limitations = packet.get("current_bounded_limitations")
    if not isinstance(limitations, dict):
        raise RuntimeError("FAIL_CLOSED: gate D decision reanchor current_bounded_limitations missing")
    if str(limitations.get("router_status", "")).strip() != "STATIC_CANONICAL_BASELINE_ONLY":
        raise RuntimeError("FAIL_CLOSED: reanchor router status must remain static canonical baseline only")
    if str(packet.get("next_lawful_move", "")).strip() != FROZEN_NEXT_LAWFUL_MOVE:
        raise RuntimeError("FAIL_CLOSED: reanchor next lawful move mismatch for frozen reconsideration hold")


def _resolve_adjudication_outcome(packet: Dict[str, Any]) -> Dict[str, str]:
    gate_requirements = packet.get("gate_requirements_satisfied")
    candidate_summary = packet.get("candidate_summary")
    if not isinstance(gate_requirements, dict):
        raise RuntimeError("FAIL_CLOSED: reconsideration input gate requirements missing")
    if not isinstance(candidate_summary, dict):
        raise RuntimeError("FAIL_CLOSED: reconsideration input candidate summary missing")

    combined_terminal_adapter_count = int(candidate_summary.get("combined_terminal_adapter_count", 0))
    introduced_new_terminal_adapter = bool(gate_requirements.get("introduced_new_terminal_adapter", False))
    expanded_terminal_adapter_count = bool(gate_requirements.get("expanded_terminal_adapter_count", False))

    if introduced_new_terminal_adapter and expanded_terminal_adapter_count and combined_terminal_adapter_count >= 4:
        return {
            "adjudication_posture": POST_THIRD_RERUN_ADJUDICATION_POSTURE,
            "next_lawful_move": POST_THIRD_RERUN_ADJUDICATION_NEXT_MOVE,
        }
    return {
        "adjudication_posture": LEGACY_ADJUDICATION_POSTURE,
        "next_lawful_move": LEGACY_ADJUDICATION_NEXT_MOVE,
    }


def _source_ref(packet: Dict[str, Any], key: str) -> str:
    source_refs = packet.get("source_packet_refs")
    if not isinstance(source_refs, dict):
        raise RuntimeError("FAIL_CLOSED: reconsideration input source_packet_refs missing")
    value = str(source_refs.get(key, "")).strip()
    if not value:
        raise RuntimeError(f"FAIL_CLOSED: reconsideration input source ref missing: {key}")
    return value


def _tools_root(root: Path) -> Path:
    nested_tools_root = root / "KT_PROD_CLEANROOM" / "tools"
    if nested_tools_root.exists():
        return nested_tools_root
    direct_tools_root = root / "tools"
    if direct_tools_root.exists():
        return direct_tools_root
    raise RuntimeError("FAIL_CLOSED: could not locate tools root for reconsideration-path enforcement")


def _normalized_tool_path(root: Path, path: Path) -> str:
    relative = path.relative_to(root).as_posix()
    if root.name == "KT_PROD_CLEANROOM":
        return f"KT_PROD_CLEANROOM/{relative}"
    return relative


def _detect_schema_emitters(root: Path) -> List[str]:
    tools_root = _tools_root(root)
    emitters: List[str] = []
    for path in tools_root.rglob("*.py"):
        if path.name == "__init__.py" or "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text, filename=path.as_posix())
        emits_schema = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            for key, value in zip(node.keys, node.values):
                if not isinstance(key, ast.Constant) or key.value != "schema_id":
                    continue
                if isinstance(value, ast.Name) and value.id == "RECONSIDERATION_INPUT_SCHEMA_ID":
                    emits_schema = True
                    break
                if isinstance(value, ast.Constant) and value.value == RECONSIDERATION_INPUT_SCHEMA_ID:
                    emits_schema = True
                    break
            if emits_schema:
                break
        if emits_schema:
            emitters.append(_normalized_tool_path(root, path))
    return sorted(set(emitters))


def _detect_schema_touchers(root: Path) -> List[str]:
    tools_root = _tools_root(root)
    touchers: List[str] = []
    for path in tools_root.rglob("*.py"):
        if path.name == "__init__.py" or "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        if RECONSIDERATION_INPUT_SCHEMA_ID in text or "router_readiness_reconsideration_input" in text:
            touchers.append(_normalized_tool_path(root, path))
    return sorted(set(touchers))


def load_validated_router_readiness_reconsideration_input(
    *,
    root: Path,
    packet_ref: str,
    gate_packet_ref: Optional[str] = None,
    candidate_refresh_packet_ref: Optional[str] = None,
    single_path_guard_receipt_ref: Optional[str] = None,
    hold_state_basis_receipt_ref: Optional[str] = None,
) -> Dict[str, Any]:
    packet = _load_json_dict(_resolve(root, packet_ref), name="router_readiness_reconsideration_input")
    resolved_gate_ref = str(gate_packet_ref or _source_ref(packet, "gate_packet_ref"))
    resolved_candidate_ref = str(candidate_refresh_packet_ref or _source_ref(packet, "candidate_refresh_packet_ref"))
    resolved_guard_ref = str(single_path_guard_receipt_ref or _source_ref(packet, "single_path_guard_receipt_ref"))
    resolved_hold_state_basis_ref = str(hold_state_basis_receipt_ref or _source_ref(packet, "hold_state_basis_receipt_ref"))
    gate_packet = _load_json_dict(_resolve(root, resolved_gate_ref), name="lab_readiness_reconsideration_gate_packet")
    candidate_packet = _load_json_dict(_resolve(root, resolved_candidate_ref), name="later_lab_readiness_refresh_packet")
    guard_packet = _load_json_dict(_resolve(root, resolved_guard_ref), name="router_readiness_reconsideration_single_path_enforcement_receipt")
    hold_state_basis_packet = _load_json_dict(
        _resolve(root, resolved_hold_state_basis_ref),
        name="hold_state_surface_basis_validation_receipt",
    )

    receipt = build_router_readiness_reconsideration_input_validation_receipt(
        root=root,
        packet=packet,
        gate_packet=gate_packet,
        candidate_refresh_packet=candidate_packet,
        single_path_guard_receipt=guard_packet,
        hold_state_basis_receipt=hold_state_basis_packet,
        packet_ref=packet_ref,
        gate_packet_ref=resolved_gate_ref,
        candidate_refresh_packet_ref=resolved_candidate_ref,
        single_path_guard_receipt_ref=resolved_guard_ref,
        hold_state_basis_receipt_ref=resolved_hold_state_basis_ref,
    )
    if str(receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: router readiness reconsideration input did not pass sanctioned consumer validation")
    return packet


def build_router_readiness_reconsideration_single_path_enforcement_receipt(*, root: Path) -> Dict[str, Any]:
    current_head = _git_head(root)
    detected_emitters = _detect_schema_emitters(root)
    detected_schema_touchers = _detect_schema_touchers(root)

    checks = [
        {
            "check_id": "single_sanctioned_emitter_uniqueness_holds_in_repo_tools",
            "pass": detected_emitters == [SANCTIONED_EMITTER_ENTRYPOINT],
        },
        {
            "check_id": "single_sanctioned_consumer_validator_is_expected_path",
            "pass": SANCTIONED_CONSUMER_VALIDATOR_ENTRYPOINT
            == "KT_PROD_CLEANROOM/tools/operator/router_readiness_reconsideration_input_validate.py",
        },
        {
            "check_id": "schema_touch_allowlist_holds_in_repo_tools",
            "pass": detected_schema_touchers == SANCTIONED_SCHEMA_TOUCHERS,
        },
        {
            "check_id": "no_extra_tool_side_reader_or_wrapper_exists",
            "pass": detected_schema_touchers == SANCTIONED_SCHEMA_TOUCHERS,
        },
    ]
    status = "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL"
    return {
        "schema_id": "kt.router_readiness_reconsideration_input_single_path_enforcement_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": status,
        "sanctioned_paths": {
            "emitter": SANCTIONED_EMITTER_ENTRYPOINT,
            "consumer_validator": SANCTIONED_CONSUMER_VALIDATOR_ENTRYPOINT,
        },
        "detected_schema_emitters": detected_emitters,
        "detected_schema_touchers": detected_schema_touchers,
        "checks": checks,
        "claim_boundary": (
            "This receipt enforces only the single sanctioned emitter/consumer path for "
            "kt.router_readiness_reconsideration_input.v1 inside tool-side code. It does not reopen the counted lane, "
            "does not count as R5 evidence, and cannot unlock R6."
        ),
        "breach_rule": (
            "Any future tool-side touch of kt.router_readiness_reconsideration_input.v1 outside the sanctioned emitter/consumer pair "
            "must be treated as a contract breach."
        ),
    }


def build_router_readiness_reconsideration_input_validation_receipt(
    *,
    root: Path,
    packet: Dict[str, Any],
    gate_packet: Dict[str, Any],
    candidate_refresh_packet: Dict[str, Any],
    single_path_guard_receipt: Dict[str, Any],
    hold_state_basis_receipt: Dict[str, Any],
    packet_ref: str,
    gate_packet_ref: str,
    candidate_refresh_packet_ref: str,
    single_path_guard_receipt_ref: str,
    hold_state_basis_receipt_ref: str,
) -> Dict[str, Any]:
    _validate_packet_schema(packet)
    _validate_gate_packet(gate_packet)
    _validate_candidate_refresh_packet(candidate_refresh_packet)
    _validate_single_path_guard_receipt(single_path_guard_receipt)

    current_head = _git_head(root)
    _validate_hold_state_basis_receipt(hold_state_basis_receipt, current_head=current_head)

    packet_contract = packet.get("single_sanctioned_path_contract")
    producer_identity = packet.get("producer_identity")
    packet_requirements = packet.get("gate_requirements_satisfied")
    candidate_terminals = candidate_refresh_packet.get("terminal_summary")
    gate_questions = gate_packet.get("questions")
    gate_source_refs = gate_packet.get("source_packet_refs")
    packet_single_path_summary = packet.get("single_path_guard_summary")
    packet_hold_state_basis_summary = packet.get("hold_state_basis_summary")
    if not isinstance(packet_contract, dict):
        raise RuntimeError("FAIL_CLOSED: reconsideration input contract block missing")
    if not isinstance(producer_identity, dict):
        raise RuntimeError("FAIL_CLOSED: reconsideration input producer identity missing")
    if not isinstance(packet_requirements, dict):
        raise RuntimeError("FAIL_CLOSED: reconsideration input gate requirements missing")
    if not isinstance(candidate_terminals, dict):
        raise RuntimeError("FAIL_CLOSED: candidate refresh terminal_summary missing")
    if not isinstance(gate_questions, dict):
        raise RuntimeError("FAIL_CLOSED: gate packet questions missing")
    if not isinstance(gate_source_refs, dict):
        raise RuntimeError("FAIL_CLOSED: gate packet source refs missing")
    if not isinstance(packet_single_path_summary, dict):
        raise RuntimeError("FAIL_CLOSED: reconsideration input single_path_guard_summary missing")
    if not isinstance(packet_hold_state_basis_summary, dict):
        raise RuntimeError("FAIL_CLOSED: reconsideration input hold_state_basis_summary missing")

    detected_emitters = _detect_schema_emitters(root)
    detected_schema_touchers = _detect_schema_touchers(root)
    packet_gate_ref = _source_ref(packet, "gate_packet_ref")
    packet_candidate_ref = _source_ref(packet, "candidate_refresh_packet_ref")
    packet_guard_ref = _source_ref(packet, "single_path_guard_receipt_ref")
    packet_hold_state_basis_ref = _source_ref(packet, "hold_state_basis_receipt_ref")
    gate_schema_id = _gate_packet_schema_id(gate_packet)
    candidate_refresh_schema_id = _candidate_refresh_packet_schema_id(candidate_refresh_packet)
    candidate_adapters = list(candidate_terminals.get("combined_terminal_adapters", []))
    candidate_adapter_count = int(candidate_terminals.get("combined_terminal_adapter_count", 0))
    candidate_head = _candidate_primary_head(candidate_refresh_packet)
    candidate_heads = _candidate_refresh_heads(candidate_refresh_packet)
    guard_head = str(single_path_guard_receipt.get("current_git_head", "")).strip()
    hold_state_actual_head = str(hold_state_basis_receipt.get("actual_repo_head", "")).strip()
    hold_state_basis_head = str(hold_state_basis_receipt.get("tracked_surface_basis_head", "")).strip()

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
            and str(packet_contract.get("required_single_path_guard_receipt_schema_id", "")).strip()
            == SINGLE_PATH_ENFORCEMENT_RECEIPT_SCHEMA_ID
            and str(packet_contract.get("required_hold_state_basis_receipt_schema_id", "")).strip()
            == HOLD_STATE_BASIS_VALIDATION_RECEIPT_SCHEMA_ID
            and str(packet_contract.get("required_gate_packet_schema_id", "")).strip()
            == gate_schema_id
            and str(packet_contract.get("required_candidate_refresh_packet_schema_id", "")).strip()
            == candidate_refresh_schema_id,
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
            and packet_guard_ref == str(single_path_guard_receipt_ref).strip()
            and packet_hold_state_basis_ref == str(hold_state_basis_receipt_ref).strip()
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
            == candidate_head
            and list(packet.get("candidate_summary", {}).get("combined_terminal_adapters", [])) == candidate_adapters
            and int(packet.get("candidate_summary", {}).get("combined_terminal_adapter_count", 0)) == candidate_adapter_count,
        },
        {
            "check_id": "single_path_guard_receipt_is_same_head_fresh",
            "pass": guard_head == current_head
            and bool(candidate_heads)
            and candidate_heads == {guard_head}
            and str(single_path_guard_receipt.get("subject_head", "")).strip() == guard_head,
        },
        {
            "check_id": "packet_single_path_guard_summary_matches_guard_receipt",
            "pass": str(packet_single_path_summary.get("guard_head", "")).strip() == guard_head
            and int(packet_single_path_summary.get("detected_schema_emitter_count", 0))
            == len(single_path_guard_receipt.get("detected_schema_emitters", []))
            and int(packet_single_path_summary.get("detected_schema_toucher_count", 0))
            == len(single_path_guard_receipt.get("detected_schema_touchers", [])),
        },
        {
            "check_id": "hold_state_basis_receipt_is_fresh_and_non_authoritative",
            "pass": hold_state_actual_head == current_head and hold_state_basis_head and hold_state_basis_head != current_head,
        },
        {
            "check_id": "packet_hold_state_basis_summary_matches_receipt",
            "pass": str(packet_hold_state_basis_summary.get("actual_repo_head", "")).strip() == hold_state_actual_head
            and str(packet_hold_state_basis_summary.get("tracked_surface_basis_head", "")).strip() == hold_state_basis_head,
        },
        {
            "check_id": "single_sanctioned_emitter_uniqueness_holds_in_repo_tools",
            "pass": detected_emitters == [SANCTIONED_EMITTER_ENTRYPOINT],
        },
        {
            "check_id": "schema_touch_allowlist_holds_in_repo_tools",
            "pass": detected_schema_touchers == SANCTIONED_SCHEMA_TOUCHERS,
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
            "single_path_guard_receipt_ref": single_path_guard_receipt_ref,
            "hold_state_basis_receipt_ref": hold_state_basis_receipt_ref,
        },
        "sanctioned_path_contract": {
            "sanctioned_emitter_entrypoint": SANCTIONED_EMITTER_ENTRYPOINT,
            "sanctioned_consumer_validator_entrypoint": SANCTIONED_CONSUMER_VALIDATOR_ENTRYPOINT,
        },
        "detected_schema_emitters": detected_emitters,
        "detected_schema_touchers": detected_schema_touchers,
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


def build_router_readiness_reconsideration_adjudication_receipt(
    *,
    root: Path,
    packet: Dict[str, Any],
    current_state_overlay: Dict[str, Any],
    next_counted_workstream_contract: Dict[str, Any],
    resume_blockers_receipt: Dict[str, Any],
    gate_d_decision_reanchor_packet: Dict[str, Any],
    packet_ref: str,
    current_state_overlay_ref: str,
    next_counted_workstream_contract_ref: str,
    resume_blockers_receipt_ref: str,
    gate_d_decision_reanchor_packet_ref: str,
) -> Dict[str, Any]:
    _validate_packet_schema(packet)
    _validate_current_state_overlay_for_reconsideration_adjudication(current_state_overlay)
    _validate_next_counted_workstream_contract_for_reconsideration_adjudication(next_counted_workstream_contract)
    _validate_resume_blockers_for_reconsideration_adjudication(resume_blockers_receipt)
    _validate_reanchor_for_reconsideration_adjudication(gate_d_decision_reanchor_packet)

    gate_requirements = packet.get("gate_requirements_satisfied")
    candidate_summary = packet.get("candidate_summary")
    single_path_guard_summary = packet.get("single_path_guard_summary")
    hold_state_basis_summary = packet.get("hold_state_basis_summary")
    if not isinstance(gate_requirements, dict):
        raise RuntimeError("FAIL_CLOSED: reconsideration input gate requirements missing")
    if not isinstance(candidate_summary, dict):
        raise RuntimeError("FAIL_CLOSED: reconsideration input candidate summary missing")
    if not isinstance(single_path_guard_summary, dict):
        raise RuntimeError("FAIL_CLOSED: reconsideration input single_path_guard_summary missing")
    if not isinstance(hold_state_basis_summary, dict):
        raise RuntimeError("FAIL_CLOSED: reconsideration input hold_state_basis_summary missing")

    current_head = _git_head(root)
    material_change_earned = bool(gate_requirements.get("material_change_earned", False))
    semantic_bypass_risk = bool(gate_requirements.get("semantic_bypass_risk", True))
    introduced_new_terminal_adapter = bool(gate_requirements.get("introduced_new_terminal_adapter", False))
    expanded_terminal_adapter_count = bool(gate_requirements.get("expanded_terminal_adapter_count", False))
    if not material_change_earned:
        raise RuntimeError("FAIL_CLOSED: reconsideration adjudication requires material_change_earned = true")
    if semantic_bypass_risk:
        raise RuntimeError("FAIL_CLOSED: reconsideration adjudication requires semantic_bypass_risk = false")
    if not introduced_new_terminal_adapter or not expanded_terminal_adapter_count:
        raise RuntimeError("FAIL_CLOSED: reconsideration adjudication requires expanded terminal diversity")

    adjudication_outcome = _resolve_adjudication_outcome(packet)
    combined_terminals = [
        str(item).strip()
        for item in candidate_summary.get("combined_terminal_adapters", [])
        if str(item).strip()
    ]
    combined_terminal_adapter_count = int(candidate_summary.get("combined_terminal_adapter_count", 0))
    candidate_head = str(candidate_summary.get("candidate_lab_head", "")).strip()
    guard_head = str(single_path_guard_summary.get("guard_head", "")).strip()
    hold_state_actual_head = str(hold_state_basis_summary.get("actual_repo_head", "")).strip()
    hold_state_basis_head = str(hold_state_basis_summary.get("tracked_surface_basis_head", "")).strip()

    checks = [
        {
            "check_id": "validated_reconsideration_input_is_present_and_passed",
            "pass": True,
        },
        {
            "check_id": "material_change_earned_without_semantic_bypass",
            "pass": material_change_earned and not semantic_bypass_risk,
        },
        {
            "check_id": "same_head_candidate_and_dual_receipts_align_on_current_head",
            "pass": bool(candidate_head)
            and candidate_head == current_head
            and guard_head == candidate_head
            and hold_state_actual_head == candidate_head,
        },
        {
            "check_id": "terminal_breadth_expanded_beyond_frozen_ceiling",
            "pass": introduced_new_terminal_adapter
            and expanded_terminal_adapter_count
            and combined_terminal_adapter_count >= 3,
        },
        {
            "check_id": "counted_lane_still_closed_and_static_baseline_still_canonical",
            "pass": (
                not bool(current_state_overlay.get("repo_state_executable_now", True))
                and not bool(next_counted_workstream_contract.get("repo_state_executable_now", True))
                and not bool(resume_blockers_receipt.get("repo_state_executable_now", True))
                and str(
                    gate_d_decision_reanchor_packet.get("current_bounded_limitations", {}).get("router_status", "")
                ).strip()
                == "STATIC_CANONICAL_BASELINE_ONLY"
            ),
        },
        {
            "check_id": "next_in_order_remains_r6_blocked",
            "pass": str(current_state_overlay.get("next_counted_workstream_id", "")).strip() == NEXT_IN_ORDER_ID
            and str(next_counted_workstream_contract.get("exact_next_counted_workstream_id", "")).strip()
            == NEXT_IN_ORDER_ID,
        },
    ]

    status = "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL"
    return {
        "schema_id": RECONSIDERATION_ADJUDICATION_RECEIPT_SCHEMA_ID,
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": status,
        "claim_boundary": (
            "This receipt adjudicates only the lab-only router-readiness reconsideration path. It does not reopen the counted lane, "
            "does not relaunch R5, does not earn router superiority, and cannot unlock R6. Its only positive outcome is whether a "
            "separate counted R5 rerun launch surface may now be considered."
        ),
        "adjudication_posture": (
            adjudication_outcome["adjudication_posture"] if status == "PASS" else "RECONSIDERATION_ADJUDICATION_FAIL_CLOSED"
        ),
        "counted_lane_recommendation": "KEEP_COUNTED_LANE_CLOSED_PENDING_SEPARATE_LAUNCH_SURFACE",
        "next_lawful_move": (
            adjudication_outcome["next_lawful_move"] if status == "PASS" else "HOLD_COUNTED_LANE_CLOSED__ADJUDICATION_NOT_EARNED"
        ),
        "current_standing_preserved": {
            "counted_lane": "CLOSED",
            "static_baseline": "CANONICAL",
            "next_in_order": NEXT_IN_ORDER_ID,
            "next_in_order_status": "BLOCKED_IN_LAW",
        },
        "adjudication_questions": {
            "validated_reconsideration_input_present": True,
            "material_change_earned": material_change_earned,
            "semantic_bypass_risk": semantic_bypass_risk,
            "introduced_new_terminal_adapter": introduced_new_terminal_adapter,
            "expanded_terminal_adapter_count": expanded_terminal_adapter_count,
            "combined_terminal_adapter_count": combined_terminal_adapter_count,
            "candidate_head_is_current_head": candidate_head == current_head,
            "dual_receipts_are_same_head_fresh": guard_head == candidate_head and hold_state_actual_head == candidate_head,
            "counted_lane_still_closed": True,
            "static_baseline_still_canonical": True,
            "r6_still_next_in_order_blocked": True,
        },
        "candidate_summary": {
            "candidate_lab_head": candidate_head,
            "combined_terminal_adapters": combined_terminals,
            "combined_terminal_adapter_count": combined_terminal_adapter_count,
        },
        "checks": checks,
        "non_authorizations": [
            "No counted reopening is authorized by this receipt alone.",
            "No B04_R5 rerun launch surface is created by this receipt alone.",
            "No B04_R5 proof rerun is executed by this receipt alone.",
            "No learned-router authorization or R6 movement is authorized.",
            "No lobe, externality, comparative, or commercial widening is authorized.",
        ],
        "source_packet_refs": {
            "reconsideration_input_ref": packet_ref,
            "current_state_overlay_ref": current_state_overlay_ref,
            "next_counted_workstream_contract_ref": next_counted_workstream_contract_ref,
            "resume_blockers_receipt_ref": resume_blockers_receipt_ref,
            "gate_d_decision_reanchor_packet_ref": gate_d_decision_reanchor_packet_ref,
        },
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate a lab-only router-readiness reconsideration input against its sanctioned emitter/consumer contract."
    )
    parser.add_argument("--input")
    parser.add_argument("--gate-packet")
    parser.add_argument("--candidate-refresh-packet")
    parser.add_argument("--single-path-guard-receipt")
    parser.add_argument("--hold-state-basis-receipt")
    parser.add_argument("--current-campaign-state-overlay", default="reports/current_campaign_state_overlay.json")
    parser.add_argument("--next-counted-workstream-contract", default="reports/next_counted_workstream_contract.json")
    parser.add_argument("--resume-blockers-receipt", default="reports/resume_blockers_receipt.json")
    parser.add_argument("--gate-d-decision-reanchor-packet", default="reports/gate_d_decision_reanchor_packet.json")
    parser.add_argument("--output", required=True)
    parser.add_argument("--emit-single-path-enforcement-receipt", action="store_true")
    parser.add_argument("--emit-adjudication-receipt", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    if args.emit_single_path_enforcement_receipt:
        receipt = build_router_readiness_reconsideration_single_path_enforcement_receipt(root=root)
        output_path = _resolve(root, str(args.output))
        write_json_stable(output_path, receipt)
        summary = {
            "status": receipt["status"],
            "detected_schema_emitter_count": len(receipt["detected_schema_emitters"]),
            "detected_schema_toucher_count": len(receipt["detected_schema_touchers"]),
        }
        print(json.dumps(summary, sort_keys=True))
        return 0 if receipt["status"] == "PASS" else 1

    if not str(args.input or "").strip():
        raise RuntimeError("FAIL_CLOSED: --input is required unless a receipt-only mode is set")

    packet_ref = str(args.input)
    gate_ref = str(args.gate_packet or "")
    candidate_ref = str(args.candidate_refresh_packet or "")
    guard_ref = str(args.single_path_guard_receipt or "")
    hold_state_basis_ref = str(args.hold_state_basis_receipt or "")

    if args.emit_adjudication_receipt:
        validated_packet = load_validated_router_readiness_reconsideration_input(
            root=root,
            packet_ref=packet_ref,
            gate_packet_ref=gate_ref or None,
            candidate_refresh_packet_ref=candidate_ref or None,
            single_path_guard_receipt_ref=guard_ref or None,
            hold_state_basis_receipt_ref=hold_state_basis_ref or None,
        )
        overlay_ref = str(args.current_campaign_state_overlay)
        next_ref = str(args.next_counted_workstream_contract)
        resume_ref = str(args.resume_blockers_receipt)
        reanchor_ref = str(args.gate_d_decision_reanchor_packet)
        receipt = build_router_readiness_reconsideration_adjudication_receipt(
            root=root,
            packet=validated_packet,
            current_state_overlay=_load_json_dict(_resolve(root, overlay_ref), name="current_campaign_state_overlay"),
            next_counted_workstream_contract=_load_json_dict(
                _resolve(root, next_ref),
                name="next_counted_workstream_contract",
            ),
            resume_blockers_receipt=_load_json_dict(_resolve(root, resume_ref), name="resume_blockers_receipt"),
            gate_d_decision_reanchor_packet=_load_json_dict(
                _resolve(root, reanchor_ref),
                name="gate_d_decision_reanchor_packet",
            ),
            packet_ref=packet_ref,
            current_state_overlay_ref=overlay_ref,
            next_counted_workstream_contract_ref=next_ref,
            resume_blockers_receipt_ref=resume_ref,
            gate_d_decision_reanchor_packet_ref=reanchor_ref,
        )
        output_path = _resolve(root, str(args.output))
        write_json_stable(output_path, receipt)
        summary = {
            "status": receipt["status"],
            "adjudication_posture": receipt["adjudication_posture"],
            "next_lawful_move": receipt["next_lawful_move"],
        }
        print(json.dumps(summary, sort_keys=True))
        return 0 if receipt["status"] == "PASS" else 1

    packet = _load_json_dict(_resolve(root, packet_ref), name="router_readiness_reconsideration_input")
    gate_ref = str(args.gate_packet or _source_ref(packet, "gate_packet_ref"))
    candidate_ref = str(args.candidate_refresh_packet or _source_ref(packet, "candidate_refresh_packet_ref"))
    guard_ref = str(args.single_path_guard_receipt or _source_ref(packet, "single_path_guard_receipt_ref"))
    hold_state_basis_ref = str(args.hold_state_basis_receipt or _source_ref(packet, "hold_state_basis_receipt_ref"))
    gate_packet = _load_json_dict(_resolve(root, gate_ref), name="lab_readiness_reconsideration_gate_packet")
    candidate_packet = _load_json_dict(_resolve(root, candidate_ref), name="later_lab_readiness_refresh_packet")
    guard_packet = _load_json_dict(_resolve(root, guard_ref), name="router_readiness_reconsideration_single_path_enforcement_receipt")
    hold_state_basis_packet = _load_json_dict(
        _resolve(root, hold_state_basis_ref),
        name="hold_state_surface_basis_validation_receipt",
    )

    receipt = build_router_readiness_reconsideration_input_validation_receipt(
        root=root,
        packet=packet,
        gate_packet=gate_packet,
        candidate_refresh_packet=candidate_packet,
        single_path_guard_receipt=guard_packet,
        hold_state_basis_receipt=hold_state_basis_packet,
        packet_ref=packet_ref,
        gate_packet_ref=gate_ref,
        candidate_refresh_packet_ref=candidate_ref,
        single_path_guard_receipt_ref=guard_ref,
        hold_state_basis_receipt_ref=hold_state_basis_ref,
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
