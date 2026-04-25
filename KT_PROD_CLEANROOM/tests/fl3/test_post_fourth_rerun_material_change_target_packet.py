from __future__ import annotations

import json
from pathlib import Path

from tools.router.run_post_fourth_rerun_material_change_target_packet import (  # noqa: E402
    build_post_fourth_rerun_material_change_target_packet,
    main,
)


def _current_state_overlay(*, include_r3: bool = True) -> dict:
    completed = [
        "B04_R1_CRUCIBLE_PRESSURE_LAW_RATIFICATION",
        "B04_R2_ADAPTER_LIFECYCLE_LAW_RATIFICATION",
        "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF__FOURTH_SAME_HEAD_RERUN",
    ]
    if include_r3:
        completed.append("B04_R3_TOURNAMENT_PROMOTION_MERGE_LAW_RATIFICATION")

    return {
        "schema_id": "kt.current_campaign_state_overlay.v1",
        "next_counted_workstream_id": "B04_R6_LEARNED_ROUTER_AUTHORIZATION",
        "repo_state_executable_now": False,
        "current_lawful_gate_standing": {
            "inter_gate_state": "GATE_D_POST_FOURTH_RERUN_STATIC_HOLD__COUNTED_LANE_CLOSED",
            "completed_tranches": completed,
        },
    }


def _refresh_packet() -> dict:
    return {
        "schema_id": "kt.fourth_terminal_lab_readiness_refresh_packet.v1",
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "source_lab_head": "HEAD_FOUR",
        "questions": {
            "same_head_across_refresh": True,
            "broader_reruns_confirmed_across_all_terminal_paths": True,
            "same_head_consistency_preserved_across_all_terminal_paths": True,
            "shadow_constraints_preserved_across_all_terminal_paths": True,
            "fresh_verified_entrants_preserved_across_all_terminal_paths": True,
            "tournament_like_constraints_passed_across_all_terminal_paths": True,
            "distinct_route_topology_visible_across_all_terminal_paths": True,
            "fourth_terminal_diversity_visible": True,
        },
        "terminal_summary": {
            "combined_terminal_adapter_count": 4,
            "combined_terminal_adapters": [
                "lobe.code.specialist.v1",
                "lobe.writer.specialist.v1",
                "lobe.math.specialist.v1",
                "lobe.research.specialist.v1",
            ],
        },
        "route_summary": {
            "combined_unique_route_pair_count": 5,
            "combined_route_pairs": [
                "lobe.math.specialist.v1 -> lobe.code.specialist.v1",
                "lobe.generalist.shadow.v1 -> lobe.code.specialist.v1",
                "lobe.research.specialist.v1 -> lobe.writer.specialist.v1",
                "lobe.generalist.shadow.v1 -> lobe.math.specialist.v1",
                "lobe.generalist.shadow.v1 -> lobe.research.specialist.v1",
            ],
        },
    }


def test_post_fourth_rerun_material_change_target_packet_selects_router_branch() -> None:
    packet = build_post_fourth_rerun_material_change_target_packet(
        current_state_overlay=_current_state_overlay(),
        fourth_terminal_refresh_packet=_refresh_packet(),
        current_state_overlay_ref="overlay.json",
        fourth_terminal_refresh_packet_ref="refresh.json",
    )

    assert packet["status"] == "PASS"
    assert packet["branch_selection_posture"] == "ROUTER_BRANCH_ONLY__NO_EARLIER_NON_ROUTER_GATE_D_PIVOT_AVAILABLE"
    assert packet["questions"]["router_branch_selected"] is True
    assert packet["questions"]["requires_new_terminal_adapter_beyond_current_four"] is True
    assert (
        "On a new lab head, introduce at least one downstream terminal adapter beyond "
        "`lobe.code.specialist.v1`, `lobe.writer.specialist.v1`, `lobe.math.specialist.v1`, and `lobe.research.specialist.v1`"
        in packet["router_material_change_target_sentence"]
    )
    assert packet["questions"]["validator_only_or_hold_only_changes_would_still_fail"] is True


def test_post_fourth_rerun_material_change_target_packet_reports_pivot_available_when_non_router_core_missing() -> None:
    packet = build_post_fourth_rerun_material_change_target_packet(
        current_state_overlay=_current_state_overlay(include_r3=False),
        fourth_terminal_refresh_packet=_refresh_packet(),
        current_state_overlay_ref="overlay.json",
        fourth_terminal_refresh_packet_ref="refresh.json",
    )

    assert packet["status"] == "PASS"
    assert packet["branch_selection_posture"] == "NON_ROUTER_GATE_D_PIVOT_STILL_AVAILABLE"
    assert packet["questions"]["pivot_branch_available"] is True
    assert packet["pivot_branch_summary"]["missing_non_router_gate_d_core_tranches"] == [
        "B04_R3_TOURNAMENT_PROMOTION_MERGE_LAW_RATIFICATION"
    ]


def test_post_fourth_rerun_material_change_target_packet_cli_writes_packet(tmp_path: Path) -> None:
    overlay_path = tmp_path / "overlay.json"
    refresh_path = tmp_path / "refresh.json"
    output_path = tmp_path / "target.json"
    overlay_path.write_text(json.dumps(_current_state_overlay(), indent=2), encoding="utf-8")
    refresh_path.write_text(json.dumps(_refresh_packet(), indent=2), encoding="utf-8")

    rc = main(
        [
            "--current-state-overlay",
            str(overlay_path),
            "--fourth-terminal-refresh-packet",
            str(refresh_path),
            "--output",
            str(output_path),
        ]
    )

    assert rc == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["questions"]["router_branch_selected"] is True
    assert payload["current_router_hold_summary"]["frozen_terminal_adapters"] == [
        "lobe.code.specialist.v1",
        "lobe.writer.specialist.v1",
        "lobe.math.specialist.v1",
        "lobe.research.specialist.v1",
    ]
