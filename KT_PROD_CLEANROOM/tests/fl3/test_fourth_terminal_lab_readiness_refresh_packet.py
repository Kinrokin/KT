from __future__ import annotations

import json
from pathlib import Path

from tools.router.run_fourth_terminal_lab_readiness_refresh_packet import (  # noqa: E402
    build_fourth_terminal_lab_readiness_refresh_packet,
    main,
)


def _packet(*, lab_head: str, terminals: list[str], route_pairs: list[str], survives: bool = True) -> dict:
    return {
        "schema_id": "kt.topology_breadth_readiness_packet.v1",
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "lab_head": lab_head,
        "questions": {
            "reproducible_across_reruns": survives,
            "same_head_lab_consistent": survives,
            "shadow_constraints_preserved": survives,
            "survives_fresh_verified_entrants": survives,
            "tournament_like_constraints_passed": survives,
            "second_distinct_topology_visible": survives,
            "downstream_terminal_diversity_earned": True,
            "not_code_specialist_dependence_in_disguise": True,
        },
        "route_topology_summary": {
            "combined_terminal_adapters": terminals,
            "combined_route_pairs": route_pairs,
        },
        "second_topology_summary": {
            "second_case_count": 3,
            "second_route_advantage_case_count": 3,
        },
    }


def test_fourth_terminal_refresh_confirms_four_terminals_on_same_head() -> None:
    packet = build_fourth_terminal_lab_readiness_refresh_packet(
        topology_packets=[
            _packet(
                lab_head="HEAD_NEW",
                terminals=["lobe.code.specialist.v1"],
                route_pairs=["lobe.math.specialist.v1 -> lobe.code.specialist.v1"],
            ),
            _packet(
                lab_head="HEAD_NEW",
                terminals=["lobe.writer.specialist.v1", "lobe.math.specialist.v1"],
                route_pairs=[
                    "lobe.research.specialist.v1 -> lobe.writer.specialist.v1",
                    "lobe.generalist.shadow.v1 -> lobe.math.specialist.v1",
                ],
            ),
            _packet(
                lab_head="HEAD_NEW",
                terminals=["lobe.writer.specialist.v1", "lobe.research.specialist.v1"],
                route_pairs=[
                    "lobe.research.specialist.v1 -> lobe.writer.specialist.v1",
                    "lobe.generalist.shadow.v1 -> lobe.research.specialist.v1",
                ],
            ),
        ],
        topology_packet_refs=["code.json", "writer_math.json", "writer_research.json"],
    )

    assert packet["status"] == "PASS"
    assert packet["refresh_posture"] == "FOURTH_TERMINAL_LAB_READINESS_REFRESH_CONFIRMED"
    assert packet["questions"]["fourth_terminal_diversity_visible"] is True
    assert packet["terminal_summary"]["combined_terminal_adapter_count"] == 4


def test_fourth_terminal_refresh_holds_when_fourth_terminal_missing() -> None:
    packet = build_fourth_terminal_lab_readiness_refresh_packet(
        topology_packets=[
            _packet(
                lab_head="HEAD_NEW",
                terminals=["lobe.code.specialist.v1"],
                route_pairs=["lobe.math.specialist.v1 -> lobe.code.specialist.v1"],
            ),
            _packet(
                lab_head="HEAD_NEW",
                terminals=["lobe.writer.specialist.v1", "lobe.math.specialist.v1"],
                route_pairs=[
                    "lobe.research.specialist.v1 -> lobe.writer.specialist.v1",
                    "lobe.generalist.shadow.v1 -> lobe.math.specialist.v1",
                ],
            ),
            _packet(
                lab_head="HEAD_NEW",
                terminals=["lobe.writer.specialist.v1"],
                route_pairs=["lobe.generalist.shadow.v1 -> lobe.writer.specialist.v1"],
            ),
        ],
        topology_packet_refs=["code.json", "writer_math.json", "writer_only.json"],
    )

    assert packet["status"] == "PASS"
    assert packet["refresh_posture"] == "HOLD_LAB_ONLY_PENDING_FOURTH_TERMINAL_REFRESH"
    assert "FOURTH_TERMINAL_DIVERSITY_NOT_VISIBLE" in packet["blockers"]


def test_fourth_terminal_refresh_cli_writes_packet(tmp_path: Path) -> None:
    paths = []
    payloads = [
        _packet(
            lab_head="HEAD_NEW",
            terminals=["lobe.code.specialist.v1"],
            route_pairs=["lobe.math.specialist.v1 -> lobe.code.specialist.v1"],
        ),
        _packet(
            lab_head="HEAD_NEW",
            terminals=["lobe.writer.specialist.v1", "lobe.math.specialist.v1"],
            route_pairs=[
                "lobe.research.specialist.v1 -> lobe.writer.specialist.v1",
                "lobe.generalist.shadow.v1 -> lobe.math.specialist.v1",
            ],
        ),
        _packet(
            lab_head="HEAD_NEW",
            terminals=["lobe.writer.specialist.v1", "lobe.research.specialist.v1"],
            route_pairs=[
                "lobe.research.specialist.v1 -> lobe.writer.specialist.v1",
                "lobe.generalist.shadow.v1 -> lobe.research.specialist.v1",
            ],
        ),
    ]
    for index, payload in enumerate(payloads, start=1):
        path = tmp_path / f"packet_{index}.json"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        paths.append(path)
    out_path = tmp_path / "refresh.json"

    rc = main(
        [
            "--topology-packet",
            str(paths[0]),
            "--topology-packet",
            str(paths[1]),
            "--topology-packet",
            str(paths[2]),
            "--output",
            str(out_path),
        ]
    )

    assert rc == 0
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["terminal_summary"]["combined_terminal_adapter_count"] == 4
