from __future__ import annotations

import json
from pathlib import Path

from tools.router.run_later_lab_readiness_refresh_packet import (  # noqa: E402
    build_later_lab_readiness_refresh_packet,
    main,
)


def _packet(*, lab_head: str, terminals: list[str], math_ok: bool) -> dict:
    return {
        "schema_id": "kt.topology_breadth_readiness_packet.v1",
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "lab_head": lab_head,
        "questions": {
            "reproducible_across_reruns": True,
            "same_head_lab_consistent": True,
            "shadow_constraints_preserved": True,
            "survives_fresh_verified_entrants": True,
            "tournament_like_constraints_passed": True,
            "second_distinct_topology_visible": True,
            "downstream_terminal_diversity_earned": math_ok,
            "not_code_specialist_dependence_in_disguise": math_ok,
        },
        "route_topology_summary": {
            "combined_terminal_adapters": terminals,
        },
        "second_topology_summary": {
            "second_case_count": 3,
            "second_route_advantage_case_count": 3,
        },
    }


def test_later_lab_readiness_refresh_packet_confirms_noncollapse() -> None:
    packet = build_later_lab_readiness_refresh_packet(
        code_terminal_packet=_packet(
            lab_head="HEAD1",
            terminals=["lobe.code.specialist.v1"],
            math_ok=False,
        ),
        math_terminal_packet=_packet(
            lab_head="HEAD1",
            terminals=["lobe.code.specialist.v1", "lobe.math.specialist.v1"],
            math_ok=True,
        ),
        code_terminal_packet_ref="code.json",
        math_terminal_packet_ref="math.json",
    )

    assert packet["status"] == "PASS"
    assert packet["questions"]["not_collapsed_back_to_code_specialist_dominance"] is True
    assert packet["refresh_posture"] == "LATER_LAB_READINESS_REFRESH_CONFIRMED"
    assert packet["terminal_summary"]["combined_terminal_adapter_count"] == 2


def test_later_lab_readiness_refresh_packet_holds_when_math_path_collapses() -> None:
    packet = build_later_lab_readiness_refresh_packet(
        code_terminal_packet=_packet(
            lab_head="HEAD1",
            terminals=["lobe.code.specialist.v1"],
            math_ok=False,
        ),
        math_terminal_packet=_packet(
            lab_head="HEAD1",
            terminals=["lobe.code.specialist.v1"],
            math_ok=False,
        ),
        code_terminal_packet_ref="code.json",
        math_terminal_packet_ref="math.json",
    )

    assert packet["status"] == "PASS"
    assert packet["questions"]["not_collapsed_back_to_code_specialist_dominance"] is False
    assert packet["refresh_posture"] == "HOLD_LAB_ONLY_PENDING_BROADER_REFRESH"
    assert "COLLAPSED_BACK_TO_CODE_SPECIALIST_DOMINANCE" in packet["blockers"]


def test_later_lab_readiness_refresh_packet_cli_writes_packet(tmp_path: Path) -> None:
    code_path = tmp_path / "code.json"
    math_path = tmp_path / "math.json"
    code_path.write_text(
        json.dumps(_packet(lab_head="HEAD2", terminals=["lobe.code.specialist.v1"], math_ok=False), indent=2),
        encoding="utf-8",
    )
    math_path.write_text(
        json.dumps(
            _packet(
                lab_head="HEAD2",
                terminals=["lobe.code.specialist.v1", "lobe.math.specialist.v1"],
                math_ok=True,
            ),
            indent=2,
        ),
        encoding="utf-8",
    )
    out_path = tmp_path / "refresh.json"

    rc = main(
        [
            "--code-terminal-packet",
            str(code_path),
            "--math-terminal-packet",
            str(math_path),
            "--output",
            str(out_path),
        ]
    )

    assert rc == 0
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["questions"]["not_collapsed_back_to_code_specialist_dominance"] is True
