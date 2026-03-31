from __future__ import annotations

import json
from pathlib import Path

from tools.router.run_post_fourth_rerun_material_change_gate_packet import (  # noqa: E402
    build_post_fourth_rerun_material_change_gate_packet,
    main,
)


def _ceiling_reconsideration_input() -> dict:
    return {
        "schema_id": "kt.router_readiness_reconsideration_input.v1",
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "candidate_summary": {
            "candidate_lab_head": "HEAD_FOUR",
            "combined_terminal_adapters": [
                "lobe.code.specialist.v1",
                "lobe.writer.specialist.v1",
                "lobe.math.specialist.v1",
                "lobe.research.specialist.v1",
            ],
            "route_pairs": [
                "lobe.math.specialist.v1 -> lobe.code.specialist.v1",
                "lobe.research.specialist.v1 -> lobe.writer.specialist.v1",
                "lobe.generalist.shadow.v1 -> lobe.math.specialist.v1",
                "lobe.generalist.shadow.v1 -> lobe.research.specialist.v1",
            ],
        },
    }


def _candidate_refresh(*, head: str = "HEAD_FOUR", include_fifth_terminal: bool = False) -> dict:
    terminals = [
        "lobe.code.specialist.v1",
        "lobe.writer.specialist.v1",
        "lobe.math.specialist.v1",
        "lobe.research.specialist.v1",
    ]
    route_pairs = [
        "lobe.math.specialist.v1 -> lobe.code.specialist.v1",
        "lobe.research.specialist.v1 -> lobe.writer.specialist.v1",
        "lobe.generalist.shadow.v1 -> lobe.math.specialist.v1",
        "lobe.generalist.shadow.v1 -> lobe.research.specialist.v1",
    ]
    if include_fifth_terminal:
        terminals.append("lobe.auditor.v1")
        route_pairs.append("lobe.censor.v1 -> lobe.auditor.v1")

    return {
        "schema_id": "kt.fifth_terminal_lab_readiness_refresh_packet.v1",
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "source_lab_head": head,
        "questions": {
            "same_head_across_refresh": True,
            "broader_reruns_confirmed_across_all_terminal_paths": True,
            "same_head_consistency_preserved_across_all_terminal_paths": True,
            "shadow_constraints_preserved_across_all_terminal_paths": True,
            "fresh_verified_entrants_preserved_across_all_terminal_paths": True,
            "tournament_like_constraints_passed_across_all_terminal_paths": True,
            "distinct_route_topology_visible_across_all_terminal_paths": True,
            "fifth_terminal_diversity_visible": include_fifth_terminal,
            "primary_candidate_terminal_visible": include_fifth_terminal,
            "primary_candidate_route_pattern_visible": include_fifth_terminal,
            "expanded_beyond_frozen_four": include_fifth_terminal,
        },
        "terminal_summary": {
            "combined_terminal_adapters": terminals,
        },
        "route_summary": {
            "combined_route_pairs": route_pairs,
        },
        "primary_candidate_summary": {
            "adapter_id": "lobe.auditor.v1",
            "recommended_route_pattern": "lobe.censor.v1 -> lobe.auditor.v1",
        },
    }


def test_post_fourth_rerun_gate_holds_same_story_on_same_head() -> None:
    packet = build_post_fourth_rerun_material_change_gate_packet(
        ceiling_reconsideration_input=_ceiling_reconsideration_input(),
        candidate_refresh_packet=_candidate_refresh(),
        ceiling_reconsideration_input_ref="ceiling.json",
        candidate_refresh_packet_ref="candidate.json",
    )

    assert packet["status"] == "PASS"
    assert packet["gate_posture"] == "HOLD_LAB_ONLY_PENDING_POST_FOURTH_RERUN_MATERIAL_CHANGE"
    assert packet["questions"]["material_change_earned"] is False
    assert "CANDIDATE_REFRESH_IS_SAME_LAB_HEAD_AS_POST_FOURTH_RERUN_CEILING" in packet["blockers"]
    assert "NO_NEW_TERMINAL_ADAPTER_BEYOND_POST_FOURTH_RERUN_CEILING" in packet["blockers"]


def test_post_fourth_rerun_gate_allows_new_fifth_terminal_on_new_head() -> None:
    packet = build_post_fourth_rerun_material_change_gate_packet(
        ceiling_reconsideration_input=_ceiling_reconsideration_input(),
        candidate_refresh_packet=_candidate_refresh(head="HEAD_FIVE", include_fifth_terminal=True),
        ceiling_reconsideration_input_ref="ceiling.json",
        candidate_refresh_packet_ref="candidate.json",
    )

    assert packet["status"] == "PASS"
    assert packet["gate_posture"] == "READY_FOR_POST_FOURTH_RERUN_ROUTER_READINESS_RECONSIDERATION_INPUT_CONSIDERATION"
    assert packet["questions"]["material_change_earned"] is True
    assert packet["candidate_summary"]["new_terminal_adapters"] == ["lobe.auditor.v1"]
    assert packet["candidate_summary"]["primary_candidate_route_pattern"] == "lobe.censor.v1 -> lobe.auditor.v1"


def test_post_fourth_rerun_gate_cli_writes_packet(tmp_path: Path) -> None:
    ceiling_path = tmp_path / "ceiling.json"
    candidate_path = tmp_path / "candidate.json"
    output_path = tmp_path / "gate.json"
    ceiling_path.write_text(json.dumps(_ceiling_reconsideration_input(), indent=2), encoding="utf-8")
    candidate_path.write_text(
        json.dumps(_candidate_refresh(head="HEAD_FIVE", include_fifth_terminal=True), indent=2),
        encoding="utf-8",
    )

    rc = main(
        [
            "--ceiling-reconsideration-input",
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
    assert payload["questions"]["material_change_earned"] is True
