from __future__ import annotations

import json
from pathlib import Path

from tools.router.run_router_material_change_target_packet import (  # noqa: E402
    build_router_material_change_target_packet,
    main,
)


def _current_state_overlay(*, include_r3: bool = True) -> dict:
    completed = [
        "B04_R1_CRUCIBLE_PRESSURE_LAW_RATIFICATION",
        "B04_R2_ADAPTER_LIFECYCLE_LAW_RATIFICATION",
    ]
    if include_r3:
        completed.append("B04_R3_TOURNAMENT_PROMOTION_MERGE_LAW_RATIFICATION")

    return {
        "schema_id": "kt.current_campaign_state_overlay.v1",
        "next_counted_workstream_id": "B04_R6_LEARNED_ROUTER_AUTHORIZATION",
        "current_lawful_gate_standing": {
            "inter_gate_state": "GATE_D_LAB_READINESS_RECONSIDERATION_GATE_FROZEN__COUNTED_LANE_CLOSED",
            "completed_tranches": completed,
        },
    }


def _gate_packet(*, include_new_terminal: bool = False) -> dict:
    terminals = [
        "lobe.code.specialist.v1",
        "lobe.math.specialist.v1",
    ]
    blockers = [
        "CANDIDATE_REFRESH_IS_SAME_LAB_HEAD_AS_CEILING",
        "NO_NEW_TERMINAL_ADAPTER_BEYOND_CEILING",
        "TERMINAL_ADAPTER_COUNT_NOT_EXPANDED",
    ]
    questions = {
        "material_change_earned": False,
        "same_head_as_ceiling": True,
        "introduced_new_terminal_adapter": False,
        "expanded_terminal_adapter_count": False,
    }
    if include_new_terminal:
        terminals.append("lobe.writer.specialist.v1")
        blockers = ["CANDIDATE_REFRESH_IS_SAME_LAB_HEAD_AS_CEILING"]
        questions["introduced_new_terminal_adapter"] = True
        questions["expanded_terminal_adapter_count"] = True

    return {
        "schema_id": "kt.lab_readiness_reconsideration_gate_packet.v1",
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "gate_posture": "HOLD_LAB_CEILING__NO_MATERIAL_CHANGE_YET",
        "blockers": blockers,
        "questions": questions,
        "ceiling_summary": {
            "ceiling_lab_head": "HEAD_A",
            "terminal_adapters": [
                "lobe.code.specialist.v1",
                "lobe.math.specialist.v1",
            ],
        },
        "candidate_summary": {
            "candidate_lab_head": "HEAD_A",
            "terminal_adapters": terminals,
        },
    }


def test_router_material_change_target_packet_selects_router_branch_when_non_router_core_complete() -> None:
    packet = build_router_material_change_target_packet(
        current_state_overlay=_current_state_overlay(),
        reconsideration_gate_packet=_gate_packet(),
        current_state_overlay_ref="overlay.json",
        reconsideration_gate_packet_ref="gate.json",
    )

    assert packet["status"] == "PASS"
    assert packet["branch_selection_posture"] == "ROUTER_BRANCH_ONLY__NO_EARLIER_NON_ROUTER_GATE_D_PIVOT_AVAILABLE"
    assert packet["questions"]["router_branch_selected"] is True
    assert packet["questions"]["pivot_branch_available"] is False
    assert (
        "On a new lab head, introduce at least one downstream terminal adapter beyond "
        "`lobe.code.specialist.v1` and `lobe.math.specialist.v1`"
        in packet["router_material_change_target_sentence"]
    )
    assert packet["questions"]["route_pair_only_novelty_would_still_fail"] is True


def test_router_material_change_target_packet_reports_pivot_available_when_non_router_core_missing() -> None:
    packet = build_router_material_change_target_packet(
        current_state_overlay=_current_state_overlay(include_r3=False),
        reconsideration_gate_packet=_gate_packet(),
        current_state_overlay_ref="overlay.json",
        reconsideration_gate_packet_ref="gate.json",
    )

    assert packet["status"] == "PASS"
    assert packet["branch_selection_posture"] == "NON_ROUTER_GATE_D_PIVOT_STILL_AVAILABLE"
    assert packet["questions"]["pivot_branch_available"] is True
    assert packet["pivot_branch_summary"]["missing_non_router_gate_d_core_tranches"] == [
        "B04_R3_TOURNAMENT_PROMOTION_MERGE_LAW_RATIFICATION"
    ]


def test_router_material_change_target_packet_cli_writes_packet(tmp_path: Path) -> None:
    overlay_path = tmp_path / "overlay.json"
    gate_path = tmp_path / "gate.json"
    output_path = tmp_path / "target.json"
    overlay_path.write_text(json.dumps(_current_state_overlay(), indent=2), encoding="utf-8")
    gate_path.write_text(json.dumps(_gate_packet(), indent=2), encoding="utf-8")

    rc = main(
        [
            "--current-state-overlay",
            str(overlay_path),
            "--reconsideration-gate-packet",
            str(gate_path),
            "--output",
            str(output_path),
        ]
    )

    assert rc == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["questions"]["router_branch_selected"] is True
    assert payload["current_router_hold_summary"]["current_gate_blockers"] == [
        "CANDIDATE_REFRESH_IS_SAME_LAB_HEAD_AS_CEILING",
        "NO_NEW_TERMINAL_ADAPTER_BEYOND_CEILING",
        "TERMINAL_ADAPTER_COUNT_NOT_EXPANDED",
    ]
