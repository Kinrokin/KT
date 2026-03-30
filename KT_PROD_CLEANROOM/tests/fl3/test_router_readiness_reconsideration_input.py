from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.router.run_router_readiness_reconsideration_input import (  # noqa: E402
    build_router_readiness_reconsideration_input,
    main,
)


def _gate_packet(*, material_change: bool = False, semantic_bypass: bool = True, candidate_ref: str = "candidate.json") -> dict:
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
    return {
        "schema_id": "kt.later_lab_readiness_refresh_packet.v1",
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "source_lab_heads": {
            "code_terminal_lab_head": "HEAD_B",
            "math_terminal_lab_head": "HEAD_B",
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


def test_reconsideration_input_fails_when_gate_not_earned() -> None:
    with pytest.raises(RuntimeError, match="material_change_earned = true"):
        build_router_readiness_reconsideration_input(
            gate_packet=_gate_packet(material_change=False, semantic_bypass=True),
            candidate_refresh_packet=_candidate_refresh(),
            gate_packet_ref="gate.json",
            candidate_refresh_packet_ref="candidate.json",
        )


def test_reconsideration_input_builds_when_gate_is_clean() -> None:
    packet = build_router_readiness_reconsideration_input(
        gate_packet=_gate_packet(material_change=True, semantic_bypass=False),
        candidate_refresh_packet=_candidate_refresh(),
        gate_packet_ref="gate.json",
        candidate_refresh_packet_ref="candidate.json",
    )

    assert packet["status"] == "PASS"
    assert packet["schema_id"] == "kt.router_readiness_reconsideration_input.v1"
    assert packet["counted_lane_recommendation"] == "KEEP_COUNTED_LANE_CLOSED_UNTIL_SEPARATE_LAWFUL_DECISION_SURFACE"
    assert packet["gate_requirements_satisfied"]["material_change_earned"] is True
    assert packet["gate_requirements_satisfied"]["semantic_bypass_risk"] is False


def test_reconsideration_input_cli_writes_packet(tmp_path: Path) -> None:
    gate_path = tmp_path / "gate.json"
    candidate_path = tmp_path / "candidate.json"
    output_path = tmp_path / "reconsider.json"
    gate_path.write_text(
        json.dumps(_gate_packet(material_change=True, semantic_bypass=False, candidate_ref=str(candidate_path)), indent=2),
        encoding="utf-8",
    )
    candidate_path.write_text(json.dumps(_candidate_refresh(), indent=2), encoding="utf-8")

    rc = main(
        [
            "--gate-packet",
            str(gate_path),
            "--candidate-refresh-packet",
            str(candidate_path),
            "--output",
            str(output_path),
        ]
    )

    assert rc == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["gate_requirements_satisfied"]["material_change_earned"] is True


def test_reconsideration_input_has_single_sanctioned_emitter() -> None:
    tools_router = Path(__file__).resolve().parents[2] / "tools" / "router"
    schema_id = "kt.router_readiness_reconsideration_input.v1"
    emitters = sorted(
        path.name
        for path in tools_router.glob("*.py")
        if path.name != "__init__.py" and schema_id in path.read_text(encoding="utf-8")
    )

    assert emitters == ["run_router_readiness_reconsideration_input.py"]
