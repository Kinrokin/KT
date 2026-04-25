from __future__ import annotations

import json
from pathlib import Path

from tools.router.run_lab_readiness_reconsideration_gate_packet import (  # noqa: E402
    build_lab_readiness_reconsideration_gate_packet,
    main,
)


def _ceiling_packet() -> dict:
    return {
        "schema_id": "kt.lab_readiness_ceiling_packet.v1",
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "source_lab_heads": {
            "code_terminal_lab_head": "HEAD_A",
            "math_terminal_lab_head": "HEAD_A",
        },
        "source_refresh_summary": {
            "terminal_summary": {
                "combined_terminal_adapters": [
                    "lobe.code.specialist.v1",
                    "lobe.math.specialist.v1",
                ]
            },
            "source_summaries": {
                "code_route_topology_summary": {
                    "combined_route_pairs": [
                        "lobe.math.specialist.v1 -> lobe.code.specialist.v1",
                        "lobe.generalist.shadow.v1 -> lobe.code.specialist.v1",
                    ]
                },
                "math_route_topology_summary": {
                    "combined_route_pairs": [
                        "lobe.math.specialist.v1 -> lobe.code.specialist.v1",
                        "lobe.generalist.shadow.v1 -> lobe.math.specialist.v1",
                    ]
                },
            },
        },
    }


def _candidate_refresh(*, head: str = "HEAD_A", include_new_terminal: bool = False) -> dict:
    terminals = [
        "lobe.code.specialist.v1",
        "lobe.math.specialist.v1",
    ]
    math_route_pairs = [
        "lobe.math.specialist.v1 -> lobe.code.specialist.v1",
        "lobe.generalist.shadow.v1 -> lobe.math.specialist.v1",
    ]
    if include_new_terminal:
        terminals.append("lobe.writer.specialist.v1")
        math_route_pairs.append("lobe.generalist.shadow.v1 -> lobe.writer.specialist.v1")

    return {
        "schema_id": "kt.later_lab_readiness_refresh_packet.v1",
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "questions": {
            "code_terminal_path_survives": True,
            "math_terminal_path_survives": True,
            "same_head_across_refresh": True,
            "broader_reruns_confirmed": True,
            "fresh_verified_entrants_preserved_across_refresh": True,
            "shadow_constraints_preserved_across_refresh": True,
            "tournament_like_constraints_passed_across_refresh": True,
            "not_collapsed_back_to_code_specialist_dominance": True,
        },
        "source_lab_heads": {
            "code_terminal_lab_head": head,
            "math_terminal_lab_head": head,
        },
        "terminal_summary": {
            "combined_terminal_adapters": terminals,
        },
        "source_summaries": {
            "code_route_topology_summary": {
                "combined_route_pairs": [
                    "lobe.math.specialist.v1 -> lobe.code.specialist.v1",
                    "lobe.generalist.shadow.v1 -> lobe.code.specialist.v1",
                ]
            },
            "math_route_topology_summary": {
                "combined_route_pairs": math_route_pairs,
            },
        },
    }


def test_reconsideration_gate_holds_same_head_same_terminals() -> None:
    packet = build_lab_readiness_reconsideration_gate_packet(
        ceiling_packet=_ceiling_packet(),
        candidate_refresh_packet=_candidate_refresh(),
        ceiling_packet_ref="ceiling.json",
        candidate_refresh_packet_ref="candidate.json",
    )

    assert packet["status"] == "PASS"
    assert packet["gate_posture"] == "HOLD_LAB_CEILING__NO_MATERIAL_CHANGE_YET"
    assert packet["counted_lane_recommendation"] == "KEEP_COUNTED_LANE_CLOSED"
    assert packet["questions"]["material_change_earned"] is False
    assert "CANDIDATE_REFRESH_IS_SAME_LAB_HEAD_AS_CEILING" in packet["blockers"]
    assert "NO_NEW_TERMINAL_ADAPTER_BEYOND_CEILING" in packet["blockers"]
    assert packet["questions"]["same_preserved_ceiling_story_under_new_label"] is True
    assert packet["questions"]["semantic_bypass_risk"] is True
    assert "SAME_PRESERVED_CEILING_STORY__NOT_MATERIAL_CHANGE" in packet["blockers"]


def test_reconsideration_gate_still_flags_same_story_on_new_head() -> None:
    packet = build_lab_readiness_reconsideration_gate_packet(
        ceiling_packet=_ceiling_packet(),
        candidate_refresh_packet=_candidate_refresh(head="HEAD_B"),
        ceiling_packet_ref="ceiling.json",
        candidate_refresh_packet_ref="candidate.json",
    )

    assert packet["status"] == "PASS"
    assert packet["gate_posture"] == "HOLD_LAB_CEILING__NO_MATERIAL_CHANGE_YET"
    assert packet["questions"]["same_head_as_ceiling"] is False
    assert packet["questions"]["same_preserved_ceiling_story_under_new_label"] is True
    assert packet["questions"]["semantic_bypass_risk"] is True
    assert packet["questions"]["material_change_earned"] is False
    assert "SAME_PRESERVED_CEILING_STORY__NOT_MATERIAL_CHANGE" in packet["blockers"]


def test_reconsideration_gate_allows_material_new_terminal_on_new_head() -> None:
    packet = build_lab_readiness_reconsideration_gate_packet(
        ceiling_packet=_ceiling_packet(),
        candidate_refresh_packet=_candidate_refresh(head="HEAD_B", include_new_terminal=True),
        ceiling_packet_ref="ceiling.json",
        candidate_refresh_packet_ref="candidate.json",
    )

    assert packet["status"] == "PASS"
    assert packet["gate_posture"] == "READY_FOR_LATER_ROUTER_READINESS_RECONSIDERATION_INPUT_CONSIDERATION"
    assert packet["questions"]["material_change_earned"] is True
    assert packet["candidate_summary"]["new_terminal_adapters"] == ["lobe.writer.specialist.v1"]


def test_reconsideration_gate_cli_writes_packet(tmp_path: Path) -> None:
    ceiling_path = tmp_path / "ceiling.json"
    candidate_path = tmp_path / "candidate.json"
    output_path = tmp_path / "gate.json"
    ceiling_path.write_text(json.dumps(_ceiling_packet(), indent=2), encoding="utf-8")
    candidate_path.write_text(json.dumps(_candidate_refresh(), indent=2), encoding="utf-8")

    rc = main(
        [
            "--ceiling-packet",
            str(ceiling_path),
            "--candidate-refresh-packet",
            str(candidate_path),
            "--output",
            str(output_path),
        ]
    )

    assert rc == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["gate_posture"] == "HOLD_LAB_CEILING__NO_MATERIAL_CHANGE_YET"
    assert payload["questions"]["same_preserved_ceiling_story_under_new_label"] is True
