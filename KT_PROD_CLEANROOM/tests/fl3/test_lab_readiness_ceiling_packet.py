from __future__ import annotations

import json
from pathlib import Path

from tools.router.run_lab_readiness_ceiling_packet import (  # noqa: E402
    build_lab_readiness_ceiling_packet,
    main,
)


def _refresh_packet(*, confirmed: bool = True, counted_closed: bool = True) -> dict:
    return {
        "schema_id": "kt.later_lab_readiness_refresh_packet.v1",
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "refresh_posture": "LATER_LAB_READINESS_REFRESH_CONFIRMED" if confirmed else "HOLD_LAB_ONLY_PENDING_BROADER_REFRESH",
        "counted_lane_recommendation": "KEEP_COUNTED_LANE_CLOSED" if counted_closed else "UNSPECIFIED",
        "questions": {
            "broader_reruns_confirmed": True,
            "code_terminal_path_survives": True,
            "fresh_verified_entrants_preserved_across_refresh": True,
            "math_terminal_path_survives": True,
            "not_collapsed_back_to_code_specialist_dominance": True,
            "same_head_across_refresh": True,
            "shadow_constraints_preserved_across_refresh": True,
            "tournament_like_constraints_passed_across_refresh": True,
        },
        "source_lab_heads": {
            "code_terminal_lab_head": "HEAD1",
            "math_terminal_lab_head": "HEAD1",
        },
        "terminal_summary": {
            "combined_terminal_adapter_count": 2,
        },
        "source_summaries": {
            "code_route_topology_summary": {},
            "math_route_topology_summary": {},
        },
    }


def test_lab_readiness_ceiling_packet_freezes_clean_refresh() -> None:
    packet = build_lab_readiness_ceiling_packet(
        later_refresh_packet=_refresh_packet(),
        later_refresh_packet_ref="later.json",
    )

    assert packet["status"] == "PASS"
    assert packet["ceiling_posture"] == "LAB_READINESS_CEILING_FROZEN"
    assert packet["counted_lane_recommendation"] == "KEEP_COUNTED_LANE_CLOSED"
    assert packet["lab_recommendation"] == "PRESERVE_AS_LAB_SIGNAL_ONLY"


def test_lab_readiness_ceiling_packet_holds_when_refresh_not_confirmed() -> None:
    packet = build_lab_readiness_ceiling_packet(
        later_refresh_packet=_refresh_packet(confirmed=False),
        later_refresh_packet_ref="later.json",
    )

    assert packet["status"] == "PASS"
    assert packet["ceiling_posture"] == "HOLD_LAB_ONLY_PENDING_CEILING_FREEZE_PREREQUISITES"
    assert "LATER_REFRESH_NOT_CONFIRMED" in packet["blockers"]


def test_lab_readiness_ceiling_packet_cli_writes_packet(tmp_path: Path) -> None:
    in_path = tmp_path / "later.json"
    out_path = tmp_path / "ceiling.json"
    in_path.write_text(json.dumps(_refresh_packet(), indent=2), encoding="utf-8")

    rc = main(
        [
            "--later-refresh-packet",
            str(in_path),
            "--output",
            str(out_path),
        ]
    )

    assert rc == 0
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["ceiling_posture"] == "LAB_READINESS_CEILING_FROZEN"
