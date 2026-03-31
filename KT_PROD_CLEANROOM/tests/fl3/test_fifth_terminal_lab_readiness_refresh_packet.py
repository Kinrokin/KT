from __future__ import annotations

import json
from pathlib import Path

from tools.router.run_fifth_terminal_lab_readiness_refresh_packet import (  # noqa: E402
    build_fifth_terminal_lab_readiness_refresh_packet,
    main,
)


def _candidate_packet() -> dict:
    return {
        "schema_id": "kt.post_fourth_rerun_fifth_terminal_candidate_packet.v1",
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "primary_candidate": {
            "adapter_id": "lobe.auditor.v1",
            "required_guard_ids": ["lobe.censor.v1"],
            "recommended_route_pattern": "lobe.censor.v1 -> lobe.auditor.v1",
            "recommended_suite_ref": "KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/ROUTER_LAB/DOWNSTREAM_DIVERSITY_AUDIT_TERMINAL_SUITE_V1.json",
        },
        "frozen_four_terminal_summary": {
            "frozen_four_terminal_lab_head": "HEAD_FOUR",
            "frozen_terminal_adapters": [
                "lobe.code.specialist.v1",
                "lobe.writer.specialist.v1",
                "lobe.math.specialist.v1",
                "lobe.research.specialist.v1",
            ],
        },
    }


def _topology_packet(*, lab_head: str, terminals: list[str], route_pairs: list[str], survives: bool = True) -> dict:
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


def test_fifth_terminal_refresh_confirms_auditor_terminal_on_same_head() -> None:
    packet = build_fifth_terminal_lab_readiness_refresh_packet(
        fifth_terminal_candidate_packet=_candidate_packet(),
        fifth_terminal_candidate_packet_ref="candidate.json",
        topology_packets=[
            _topology_packet(
                lab_head="HEAD_FIVE",
                terminals=["lobe.code.specialist.v1"],
                route_pairs=["lobe.math.specialist.v1 -> lobe.code.specialist.v1"],
            ),
            _topology_packet(
                lab_head="HEAD_FIVE",
                terminals=["lobe.writer.specialist.v1", "lobe.math.specialist.v1"],
                route_pairs=[
                    "lobe.research.specialist.v1 -> lobe.writer.specialist.v1",
                    "lobe.generalist.shadow.v1 -> lobe.math.specialist.v1",
                ],
            ),
            _topology_packet(
                lab_head="HEAD_FIVE",
                terminals=["lobe.research.specialist.v1"],
                route_pairs=["lobe.generalist.shadow.v1 -> lobe.research.specialist.v1"],
            ),
            _topology_packet(
                lab_head="HEAD_FIVE",
                terminals=["lobe.auditor.v1"],
                route_pairs=["lobe.censor.v1 -> lobe.auditor.v1"],
            ),
        ],
        topology_packet_refs=["code.json", "writer_math.json", "research.json", "audit.json"],
    )

    assert packet["status"] == "PASS"
    assert packet["refresh_posture"] == "FIFTH_TERMINAL_LAB_READINESS_REFRESH_CONFIRMED"
    assert packet["questions"]["fifth_terminal_diversity_visible"] is True
    assert packet["questions"]["primary_candidate_terminal_visible"] is True
    assert packet["questions"]["primary_candidate_route_pattern_visible"] is True
    assert packet["terminal_summary"]["combined_terminal_adapter_count"] == 5


def test_fifth_terminal_refresh_holds_when_auditor_route_is_missing() -> None:
    packet = build_fifth_terminal_lab_readiness_refresh_packet(
        fifth_terminal_candidate_packet=_candidate_packet(),
        fifth_terminal_candidate_packet_ref="candidate.json",
        topology_packets=[
            _topology_packet(
                lab_head="HEAD_FIVE",
                terminals=["lobe.code.specialist.v1"],
                route_pairs=["lobe.math.specialist.v1 -> lobe.code.specialist.v1"],
            ),
            _topology_packet(
                lab_head="HEAD_FIVE",
                terminals=["lobe.writer.specialist.v1", "lobe.math.specialist.v1"],
                route_pairs=[
                    "lobe.research.specialist.v1 -> lobe.writer.specialist.v1",
                    "lobe.generalist.shadow.v1 -> lobe.math.specialist.v1",
                ],
            ),
            _topology_packet(
                lab_head="HEAD_FIVE",
                terminals=["lobe.research.specialist.v1"],
                route_pairs=["lobe.generalist.shadow.v1 -> lobe.research.specialist.v1"],
            ),
            _topology_packet(
                lab_head="HEAD_FIVE",
                terminals=["lobe.auditor.v1"],
                route_pairs=["lobe.generalist.shadow.v1 -> lobe.auditor.v1"],
            ),
        ],
        topology_packet_refs=["code.json", "writer_math.json", "research.json", "audit.json"],
    )

    assert packet["status"] == "PASS"
    assert packet["refresh_posture"] == "HOLD_LAB_ONLY_PENDING_FIFTH_TERMINAL_REFRESH"
    assert "PRIMARY_CANDIDATE_ROUTE_PATTERN_NOT_VISIBLE" in packet["blockers"]


def test_fifth_terminal_refresh_cli_writes_packet(tmp_path: Path) -> None:
    candidate_path = tmp_path / "candidate.json"
    candidate_path.write_text(json.dumps(_candidate_packet(), indent=2), encoding="utf-8")
    paths = []
    payloads = [
        _topology_packet(
            lab_head="HEAD_FIVE",
            terminals=["lobe.code.specialist.v1"],
            route_pairs=["lobe.math.specialist.v1 -> lobe.code.specialist.v1"],
        ),
        _topology_packet(
            lab_head="HEAD_FIVE",
            terminals=["lobe.writer.specialist.v1", "lobe.math.specialist.v1"],
            route_pairs=[
                "lobe.research.specialist.v1 -> lobe.writer.specialist.v1",
                "lobe.generalist.shadow.v1 -> lobe.math.specialist.v1",
            ],
        ),
        _topology_packet(
            lab_head="HEAD_FIVE",
            terminals=["lobe.research.specialist.v1"],
            route_pairs=["lobe.generalist.shadow.v1 -> lobe.research.specialist.v1"],
        ),
        _topology_packet(
            lab_head="HEAD_FIVE",
            terminals=["lobe.auditor.v1"],
            route_pairs=["lobe.censor.v1 -> lobe.auditor.v1"],
        ),
    ]
    for index, payload in enumerate(payloads, start=1):
        path = tmp_path / f"packet_{index}.json"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        paths.append(path)

    out_path = tmp_path / "refresh.json"
    rc = main(
        [
            "--fifth-terminal-candidate-packet",
            str(candidate_path),
            "--topology-packet",
            str(paths[0]),
            "--topology-packet",
            str(paths[1]),
            "--topology-packet",
            str(paths[2]),
            "--topology-packet",
            str(paths[3]),
            "--output",
            str(out_path),
        ]
    )

    assert rc == 0
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["terminal_summary"]["combined_terminal_adapter_count"] == 5
