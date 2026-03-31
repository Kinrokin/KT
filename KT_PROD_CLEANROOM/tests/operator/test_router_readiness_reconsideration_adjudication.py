from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import router_readiness_reconsideration_input_validate as validate


def _reconsideration_input() -> dict:
    return {
        "schema_id": "kt.router_readiness_reconsideration_input.v1",
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "counted_lane_recommendation": "KEEP_COUNTED_LANE_CLOSED_UNTIL_SEPARATE_LAWFUL_DECISION_SURFACE",
        "gate_requirements_satisfied": {
            "material_change_earned": True,
            "semantic_bypass_risk": False,
            "introduced_new_terminal_adapter": True,
            "expanded_terminal_adapter_count": True,
        },
        "candidate_summary": {
            "candidate_lab_head": "HEAD_X",
            "combined_terminal_adapters": [
                "lobe.code.specialist.v1",
                "lobe.math.specialist.v1",
                "lobe.writer.specialist.v1",
            ],
            "combined_terminal_adapter_count": 3,
        },
        "single_path_guard_summary": {
            "guard_head": "HEAD_X",
            "detected_schema_emitter_count": 1,
            "detected_schema_toucher_count": 2,
        },
        "hold_state_basis_summary": {
            "actual_repo_head": "HEAD_X",
            "tracked_surface_basis_head": "OLDER_HEAD",
        },
    }


def _current_state_overlay() -> dict:
    return {
        "schema_id": "kt.current_campaign_state_overlay.v1",
        "repo_state_executable_now": False,
        "next_counted_workstream_id": "B04_R6_LEARNED_ROUTER_AUTHORIZATION",
        "current_lawful_gate_standing": {
            "inter_gate_state": "GATE_D_LAB_READINESS_RECONSIDERATION_GATE_FROZEN__COUNTED_LANE_CLOSED",
        },
    }


def _next_contract() -> dict:
    return {
        "schema_id": "kt.next_counted_workstream_contract.v1",
        "repo_state_executable_now": False,
        "exact_next_counted_workstream_id": "B04_R6_LEARNED_ROUTER_AUTHORIZATION",
    }


def _resume_blockers() -> dict:
    return {
        "schema_id": "kt.resume_blockers_receipt.v1",
        "status": "PASS",
        "repo_state_executable_now": False,
        "blocking_state": "LAB_READINESS_RECONSIDERATION_GATE_FROZEN__COUNTED_LANE_CLOSED__R6_STILL_BLOCKED_PENDING_EARNED_SUPERIORITY",
    }


def _reanchor() -> dict:
    return {
        "schema_id": "kt.gate_d.decision_reanchor_packet.v1",
        "next_lawful_move": "HOLD_LAB_READINESS_CEILING_AND_RECONSIDERATION_GATE__COUNTED_LANE_CLOSED__R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF",
        "current_bounded_limitations": {
            "router_status": "STATIC_CANONICAL_BASELINE_ONLY",
        },
    }


def test_reconsideration_adjudication_receipt_passes_on_clean_input(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(validate, "_git_head", lambda _root: "HEAD_X")

    receipt = validate.build_router_readiness_reconsideration_adjudication_receipt(
        root=tmp_path,
        packet=_reconsideration_input(),
        current_state_overlay=_current_state_overlay(),
        next_counted_workstream_contract=_next_contract(),
        resume_blockers_receipt=_resume_blockers(),
        gate_d_decision_reanchor_packet=_reanchor(),
        packet_ref="input.json",
        current_state_overlay_ref="overlay.json",
        next_counted_workstream_contract_ref="next.json",
        resume_blockers_receipt_ref="resume.json",
        gate_d_decision_reanchor_packet_ref="reanchor.json",
    )

    assert receipt["status"] == "PASS"
    assert receipt["adjudication_posture"] == validate.ADJUDICATION_POSTURE
    assert receipt["next_lawful_move"] == validate.ADJUDICATION_NEXT_MOVE


def test_reconsideration_adjudication_receipt_uses_fourth_rerun_posture_for_four_terminal_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(validate, "_git_head", lambda _root: "HEAD_X")
    packet = _reconsideration_input()
    packet["candidate_summary"]["combined_terminal_adapters"].append("lobe.research.specialist.v1")
    packet["candidate_summary"]["combined_terminal_adapter_count"] = 4

    receipt = validate.build_router_readiness_reconsideration_adjudication_receipt(
        root=tmp_path,
        packet=packet,
        current_state_overlay=_current_state_overlay(),
        next_counted_workstream_contract=_next_contract(),
        resume_blockers_receipt=_resume_blockers(),
        gate_d_decision_reanchor_packet=_reanchor(),
        packet_ref="input.json",
        current_state_overlay_ref="overlay.json",
        next_counted_workstream_contract_ref="next.json",
        resume_blockers_receipt_ref="resume.json",
        gate_d_decision_reanchor_packet_ref="reanchor.json",
    )

    assert receipt["status"] == "PASS"
    assert receipt["adjudication_posture"] == validate.POST_THIRD_RERUN_ADJUDICATION_POSTURE
    assert receipt["next_lawful_move"] == validate.POST_THIRD_RERUN_ADJUDICATION_NEXT_MOVE


def test_reconsideration_adjudication_receipt_fails_when_overlay_not_frozen(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(validate, "_git_head", lambda _root: "HEAD_X")
    overlay = _current_state_overlay()
    overlay["current_lawful_gate_standing"]["inter_gate_state"] = "OTHER_STATE"

    with pytest.raises(RuntimeError, match="frozen reconsideration posture"):
        validate.build_router_readiness_reconsideration_adjudication_receipt(
            root=tmp_path,
            packet=_reconsideration_input(),
            current_state_overlay=overlay,
            next_counted_workstream_contract=_next_contract(),
            resume_blockers_receipt=_resume_blockers(),
            gate_d_decision_reanchor_packet=_reanchor(),
            packet_ref="input.json",
            current_state_overlay_ref="overlay.json",
            next_counted_workstream_contract_ref="next.json",
            resume_blockers_receipt_ref="resume.json",
            gate_d_decision_reanchor_packet_ref="reanchor.json",
        )


def test_reconsideration_adjudication_cli_emits_pass_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    input_path = tmp_path / "input.json"
    overlay_path = tmp_path / "overlay.json"
    next_path = tmp_path / "next.json"
    resume_path = tmp_path / "resume.json"
    reanchor_path = tmp_path / "reanchor.json"
    output_path = tmp_path / "receipt.json"

    input_path.write_text(json.dumps(_reconsideration_input(), indent=2), encoding="utf-8")
    overlay_path.write_text(json.dumps(_current_state_overlay(), indent=2), encoding="utf-8")
    next_path.write_text(json.dumps(_next_contract(), indent=2), encoding="utf-8")
    resume_path.write_text(json.dumps(_resume_blockers(), indent=2), encoding="utf-8")
    reanchor_path.write_text(json.dumps(_reanchor(), indent=2), encoding="utf-8")

    monkeypatch.setattr(validate, "_git_head", lambda _root: "HEAD_X")
    monkeypatch.setattr(
        validate,
        "load_validated_router_readiness_reconsideration_input",
        lambda **_kwargs: _reconsideration_input(),
    )

    rc = validate.main(
        [
            "--emit-adjudication-receipt",
            "--input",
            str(input_path),
            "--gate-packet",
            "gate.json",
            "--candidate-refresh-packet",
            "candidate.json",
            "--single-path-guard-receipt",
            "guard.json",
            "--hold-state-basis-receipt",
            "hold.json",
            "--current-campaign-state-overlay",
            str(overlay_path),
            "--next-counted-workstream-contract",
            str(next_path),
            "--resume-blockers-receipt",
            str(resume_path),
            "--gate-d-decision-reanchor-packet",
            str(reanchor_path),
            "--output",
            str(output_path),
        ]
    )

    assert rc == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["adjudication_posture"] == validate.ADJUDICATION_POSTURE
