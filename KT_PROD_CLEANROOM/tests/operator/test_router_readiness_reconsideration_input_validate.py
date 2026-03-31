from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tools.operator import router_readiness_reconsideration_input_validate as validate
from tools.router.run_router_readiness_reconsideration_input import (
    HOLD_STATE_BASIS_VALIDATION_RECEIPT_SCHEMA_ID,
    SINGLE_PATH_ENFORCEMENT_RECEIPT_SCHEMA_ID,
    SANCTIONED_CONSUMER_VALIDATOR_ENTRYPOINT,
    SANCTIONED_EMITTER_ENTRYPOINT,
    build_router_readiness_reconsideration_input,
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _repo_head() -> str:
    return subprocess.check_output(["git", "-C", str(_repo_root()), "rev-parse", "HEAD"], text=True).strip()


def _gate_packet(*, material_change: bool = True, semantic_bypass: bool = False, candidate_ref: str = "candidate.json") -> dict:
    return {
        "schema_id": "kt.lab_readiness_reconsideration_gate_packet.v1",
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "questions": {
            "material_change_earned": material_change,
            "semantic_bypass_risk": semantic_bypass,
            "same_head_as_ceiling": False,
            "introduced_new_terminal_adapter": True,
            "expanded_terminal_adapter_count": True,
            "introduced_new_route_pair": True,
            "expanded_route_pair_count": True,
        },
        "source_packet_refs": {
            "candidate_refresh_packet_ref": candidate_ref,
        },
    }


def _candidate_refresh() -> dict:
    head = _repo_head()
    return {
        "schema_id": "kt.later_lab_readiness_refresh_packet.v1",
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "source_lab_heads": {
            "code_terminal_lab_head": head,
            "math_terminal_lab_head": head,
        },
        "terminal_summary": {
            "combined_terminal_adapters": [
                "lobe.code.specialist.v1",
                "lobe.math.specialist.v1",
                "lobe.writer.specialist.v1",
            ],
            "combined_terminal_adapter_count": 3,
        },
    }


def _single_path_guard_receipt(*, head: str | None = None) -> dict:
    current_head = head or _repo_head()
    return {
        "schema_id": SINGLE_PATH_ENFORCEMENT_RECEIPT_SCHEMA_ID,
        "generated_utc": "2026-03-30T00:00:00Z",
        "current_git_head": current_head,
        "subject_head": current_head,
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "sanctioned_paths": {
            "emitter": SANCTIONED_EMITTER_ENTRYPOINT,
            "consumer_validator": SANCTIONED_CONSUMER_VALIDATOR_ENTRYPOINT,
        },
        "detected_schema_emitters": [SANCTIONED_EMITTER_ENTRYPOINT],
        "detected_schema_touchers": [
            SANCTIONED_CONSUMER_VALIDATOR_ENTRYPOINT,
            SANCTIONED_EMITTER_ENTRYPOINT,
        ],
    }


def _hold_state_basis_receipt(*, actual_head: str | None = None, tracked_basis_head: str = "PRESEAL_BASIS_HEAD") -> dict:
    current_head = actual_head or _repo_head()
    return {
        "schema_id": HOLD_STATE_BASIS_VALIDATION_RECEIPT_SCHEMA_ID,
        "generated_utc": "2026-03-30T00:00:00Z",
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "head_alignment_posture": "PRE_SEAL_HOLD_STATE_BASIS_CONFIRMED",
        "actual_repo_head": current_head,
        "tracked_surface_basis_head": tracked_basis_head,
        "resolution_rule": (
            "Treat the tracked hold surfaces as pre-seal basis only. Any future router-readiness reconsideration attempt "
            "must re-emit the single-path guard on the actual candidate head before prepare or consume may proceed."
        ),
    }


def test_reconsideration_input_validation_receipt_passes_for_clean_packet() -> None:
    root = _repo_root()
    packet = build_router_readiness_reconsideration_input(
        current_git_head=_repo_head(),
        gate_packet=_gate_packet(material_change=True, semantic_bypass=False),
        candidate_refresh_packet=_candidate_refresh(),
        single_path_guard_receipt=_single_path_guard_receipt(),
        hold_state_basis_receipt=_hold_state_basis_receipt(),
        gate_packet_ref="gate.json",
        candidate_refresh_packet_ref="candidate.json",
        single_path_guard_receipt_ref="guard.json",
        hold_state_basis_receipt_ref="hold_state_basis.json",
    )

    receipt = validate.build_router_readiness_reconsideration_input_validation_receipt(
        root=root,
        packet=packet,
        gate_packet=_gate_packet(material_change=True, semantic_bypass=False),
        candidate_refresh_packet=_candidate_refresh(),
        single_path_guard_receipt=_single_path_guard_receipt(),
        hold_state_basis_receipt=_hold_state_basis_receipt(),
        packet_ref="reconsideration.json",
        gate_packet_ref="gate.json",
        candidate_refresh_packet_ref="candidate.json",
        single_path_guard_receipt_ref="guard.json",
        hold_state_basis_receipt_ref="hold_state_basis.json",
    )

    assert receipt["status"] == "PASS"
    assert receipt["sanctioned_path_contract"]["sanctioned_emitter_entrypoint"] == SANCTIONED_EMITTER_ENTRYPOINT
    assert receipt["sanctioned_path_contract"]["sanctioned_consumer_validator_entrypoint"] == SANCTIONED_CONSUMER_VALIDATOR_ENTRYPOINT
    assert receipt["detected_schema_emitters"] == [SANCTIONED_EMITTER_ENTRYPOINT]
    assert receipt["detected_schema_touchers"] == [
        SANCTIONED_CONSUMER_VALIDATOR_ENTRYPOINT,
        SANCTIONED_EMITTER_ENTRYPOINT,
    ]


def test_reconsideration_input_validation_receipt_fails_on_contract_tamper() -> None:
    root = _repo_root()
    packet = build_router_readiness_reconsideration_input(
        current_git_head=_repo_head(),
        gate_packet=_gate_packet(material_change=True, semantic_bypass=False),
        candidate_refresh_packet=_candidate_refresh(),
        single_path_guard_receipt=_single_path_guard_receipt(),
        hold_state_basis_receipt=_hold_state_basis_receipt(),
        gate_packet_ref="gate.json",
        candidate_refresh_packet_ref="candidate.json",
        single_path_guard_receipt_ref="guard.json",
        hold_state_basis_receipt_ref="hold_state_basis.json",
    )
    packet["single_sanctioned_path_contract"]["sanctioned_consumer_validator_entrypoint"] = (
        "KT_PROD_CLEANROOM/tools/operator/alternate_validator.py"
    )

    receipt = validate.build_router_readiness_reconsideration_input_validation_receipt(
        root=root,
        packet=packet,
        gate_packet=_gate_packet(material_change=True, semantic_bypass=False),
        candidate_refresh_packet=_candidate_refresh(),
        single_path_guard_receipt=_single_path_guard_receipt(),
        hold_state_basis_receipt=_hold_state_basis_receipt(),
        packet_ref="reconsideration.json",
        gate_packet_ref="gate.json",
        candidate_refresh_packet_ref="candidate.json",
        single_path_guard_receipt_ref="guard.json",
        hold_state_basis_receipt_ref="hold_state_basis.json",
    )

    assert receipt["status"] == "FAIL"
    failed = {item["check_id"] for item in receipt["checks"] if not item["pass"]}
    assert "single_sanctioned_path_contract_matches_expected_pair" in failed


def test_reconsideration_input_validator_cli_emits_pass_receipt(tmp_path: Path) -> None:
    gate_path = tmp_path / "gate.json"
    candidate_path = tmp_path / "candidate.json"
    guard_path = tmp_path / "guard.json"
    hold_state_basis_path = tmp_path / "hold_state_basis.json"
    packet_path = tmp_path / "reconsideration.json"
    receipt_path = tmp_path / "validation.json"

    gate_packet = _gate_packet(material_change=True, semantic_bypass=False, candidate_ref=str(candidate_path))
    candidate_refresh = _candidate_refresh()
    packet = build_router_readiness_reconsideration_input(
        current_git_head=_repo_head(),
        gate_packet=gate_packet,
        candidate_refresh_packet=candidate_refresh,
        single_path_guard_receipt=_single_path_guard_receipt(),
        hold_state_basis_receipt=_hold_state_basis_receipt(),
        gate_packet_ref=str(gate_path),
        candidate_refresh_packet_ref=str(candidate_path),
        single_path_guard_receipt_ref=str(guard_path),
        hold_state_basis_receipt_ref=str(hold_state_basis_path),
    )

    gate_path.write_text(json.dumps(gate_packet, indent=2), encoding="utf-8")
    candidate_path.write_text(json.dumps(candidate_refresh, indent=2), encoding="utf-8")
    guard_path.write_text(json.dumps(_single_path_guard_receipt(), indent=2), encoding="utf-8")
    hold_state_basis_path.write_text(json.dumps(_hold_state_basis_receipt(), indent=2), encoding="utf-8")
    packet_path.write_text(json.dumps(packet, indent=2), encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.router_readiness_reconsideration_input_validate",
            "--input",
            str(packet_path),
            "--output",
            str(receipt_path),
        ],
        cwd=str(_repo_root() / "KT_PROD_CLEANROOM"),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout
    payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["detected_schema_emitters"] == [SANCTIONED_EMITTER_ENTRYPOINT]


def test_load_validated_reconsideration_input_fails_closed_through_validator_contract(tmp_path: Path) -> None:
    gate_path = tmp_path / "gate.json"
    candidate_path = tmp_path / "candidate.json"
    guard_path = tmp_path / "guard.json"
    hold_state_basis_path = tmp_path / "hold_state_basis.json"
    packet_path = tmp_path / "reconsideration.json"

    gate_packet = _gate_packet(material_change=True, semantic_bypass=False, candidate_ref=str(candidate_path))
    candidate_refresh = _candidate_refresh()
    packet = build_router_readiness_reconsideration_input(
        current_git_head=_repo_head(),
        gate_packet=gate_packet,
        candidate_refresh_packet=candidate_refresh,
        single_path_guard_receipt=_single_path_guard_receipt(),
        hold_state_basis_receipt=_hold_state_basis_receipt(),
        gate_packet_ref=str(gate_path),
        candidate_refresh_packet_ref=str(candidate_path),
        single_path_guard_receipt_ref=str(guard_path),
        hold_state_basis_receipt_ref=str(hold_state_basis_path),
    )

    gate_path.write_text(json.dumps(gate_packet, indent=2), encoding="utf-8")
    candidate_path.write_text(json.dumps(candidate_refresh, indent=2), encoding="utf-8")
    guard_path.write_text(json.dumps(_single_path_guard_receipt(), indent=2), encoding="utf-8")
    hold_state_basis_path.write_text(json.dumps(_hold_state_basis_receipt(), indent=2), encoding="utf-8")
    packet_path.write_text(json.dumps(packet, indent=2), encoding="utf-8")

    loaded = validate.load_validated_router_readiness_reconsideration_input(
        root=_repo_root(),
        packet_ref=str(packet_path),
    )

    assert loaded["schema_id"] == "kt.router_readiness_reconsideration_input.v1"


def test_reconsideration_input_validation_receipt_fails_on_stale_guard_head() -> None:
    root = _repo_root()
    packet = build_router_readiness_reconsideration_input(
        current_git_head=_repo_head(),
        gate_packet=_gate_packet(material_change=True, semantic_bypass=False),
        candidate_refresh_packet=_candidate_refresh(),
        single_path_guard_receipt=_single_path_guard_receipt(),
        hold_state_basis_receipt=_hold_state_basis_receipt(),
        gate_packet_ref="gate.json",
        candidate_refresh_packet_ref="candidate.json",
        single_path_guard_receipt_ref="guard.json",
        hold_state_basis_receipt_ref="hold_state_basis.json",
    )

    stale_guard = _single_path_guard_receipt(head="STALE_HEAD")
    receipt = validate.build_router_readiness_reconsideration_input_validation_receipt(
        root=root,
        packet=packet,
        gate_packet=_gate_packet(material_change=True, semantic_bypass=False),
        candidate_refresh_packet=_candidate_refresh(),
        single_path_guard_receipt=stale_guard,
        hold_state_basis_receipt=_hold_state_basis_receipt(),
        packet_ref="reconsideration.json",
        gate_packet_ref="gate.json",
        candidate_refresh_packet_ref="candidate.json",
        single_path_guard_receipt_ref="guard.json",
        hold_state_basis_receipt_ref="hold_state_basis.json",
    )

    assert receipt["status"] == "FAIL"
    failed = {item["check_id"] for item in receipt["checks"] if not item["pass"]}
    assert "single_path_guard_receipt_is_same_head_fresh" in failed


def test_reconsideration_input_validation_receipt_fails_when_hold_state_basis_receipt_is_treated_as_same_head_authority() -> None:
    root = _repo_root()
    packet = build_router_readiness_reconsideration_input(
        current_git_head=_repo_head(),
        gate_packet=_gate_packet(material_change=True, semantic_bypass=False),
        candidate_refresh_packet=_candidate_refresh(),
        single_path_guard_receipt=_single_path_guard_receipt(),
        hold_state_basis_receipt=_hold_state_basis_receipt(),
        gate_packet_ref="gate.json",
        candidate_refresh_packet_ref="candidate.json",
        single_path_guard_receipt_ref="guard.json",
        hold_state_basis_receipt_ref="hold_state_basis.json",
    )

    collapsed_hold_state_basis = _hold_state_basis_receipt(
        actual_head=_repo_head(),
        tracked_basis_head=_repo_head(),
    )
    try:
        validate.build_router_readiness_reconsideration_input_validation_receipt(
            root=root,
            packet=packet,
            gate_packet=_gate_packet(material_change=True, semantic_bypass=False),
            candidate_refresh_packet=_candidate_refresh(),
            single_path_guard_receipt=_single_path_guard_receipt(),
            hold_state_basis_receipt=collapsed_hold_state_basis,
            packet_ref="reconsideration.json",
            gate_packet_ref="gate.json",
            candidate_refresh_packet_ref="candidate.json",
            single_path_guard_receipt_ref="guard.json",
            hold_state_basis_receipt_ref="hold_state_basis.json",
        )
    except RuntimeError as exc:
        assert "cannot act as same-head authority" in str(exc)
    else:
        raise AssertionError("expected fail-closed hold-state basis authority rejection")
