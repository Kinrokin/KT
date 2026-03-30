from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

bootstrap_syspath()

from tools.router.run_r5_rerun_readiness_refresh_packet import (  # noqa: E402
    build_r5_rerun_readiness_refresh_packet,
    main,
)


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _base_packet(*, clean: bool = True, head: str = "abc123") -> dict:
    return {
        "schema_id": "kt.r5_rerun_readiness_packet.v1",
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "lab_head": head,
        "readiness_posture": "READY_FOR_COUNTED_R5_RERUN_CONSIDERATION" if clean else "HOLD_LAB_ONLY_PENDING_ADDITIONAL_CONFIRMATION",
        "questions": {
            "same_head_lab_consistent": True,
            "shadow_constraints_preserved": clean,
            "survives_fresh_verified_entrants": clean,
        },
        "lab_signal_summaries": {
            "scorecard_summary": {"case_count": 4},
            "tie_router_summary": {"case_count": 6},
        },
    }


def _role_packet(*, clean: bool = True, head: str = "abc123") -> dict:
    return {
        "schema_id": "kt.role_separated_router_survival_packet.v1",
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "lab_head": head,
        "posture": "LAB_ROLE_SEPARATED_SURVIVAL_CONFIRMED" if clean else "HOLD_LAB_ONLY_PENDING_ROLE_SEPARATED_REWORK",
        "questions": {
            "same_head_lab_consistent": True,
            "shadow_constraints_preserved": clean,
            "survives_fresh_verified_entrants": clean,
            "tournament_like_constraints_passed": clean,
        },
        "role_separated_summary": {"case_count": 5},
        "tournament_like_assessment": {"tournament_like_constraints_passed": clean},
    }


def test_r5_rerun_readiness_refresh_packet_can_pass_with_clean_sources() -> None:
    packet = build_r5_rerun_readiness_refresh_packet(
        base_readiness_packet=_base_packet(),
        role_separated_survival_packet=_role_packet(),
        base_readiness_packet_ref="base.json",
        role_separated_survival_packet_ref="role.json",
    )

    assert packet["status"] == "PASS"
    assert packet["questions"]["base_readiness_clean"] is True
    assert packet["questions"]["role_separated_survival_confirmed"] is True
    assert packet["questions"]["source_packets_individually_same_head_consistent"] is True
    assert packet["questions"]["source_packets_same_lab_head"] is True
    assert packet["questions"]["role_separated_tournament_like_constraints_passed"] is True
    assert packet["readiness_posture"] == "READY_FOR_SEPARATE_COUNTED_R5_RERUN_LAUNCH_SURFACE_CONSIDERATION"
    assert packet["blockers"] == []


def test_r5_rerun_readiness_refresh_packet_holds_when_role_signal_is_not_clean() -> None:
    packet = build_r5_rerun_readiness_refresh_packet(
        base_readiness_packet=_base_packet(),
        role_separated_survival_packet=_role_packet(clean=False, head="def456"),
        base_readiness_packet_ref="base.json",
        role_separated_survival_packet_ref="role.json",
    )

    assert packet["status"] == "PASS"
    assert packet["questions"]["role_separated_survival_confirmed"] is False
    assert packet["questions"]["source_packets_same_lab_head"] is False
    assert packet["readiness_posture"] == "HOLD_LAB_ONLY_PENDING_ADDITIONAL_CONFIRMATION"
    assert "ROLE_SEPARATED_SURVIVAL_NOT_CONFIRMED" in packet["blockers"]
    assert "FRESH_VERIFIED_ENTRANT_SURVIVAL_NOT_CONFIRMED_ACROSS_REFRESH" in packet["blockers"]


def test_r5_rerun_readiness_refresh_packet_cli_writes_packet(tmp_path: Path) -> None:
    base_path = tmp_path / "base.json"
    role_path = tmp_path / "role.json"
    _write_json(base_path, _base_packet())
    _write_json(role_path, _role_packet())

    out_path = tmp_path / "r5_rerun_readiness_refresh_packet.json"
    rc = main(
        [
            "--base-readiness-packet",
            str(base_path),
            "--role-separated-survival-packet",
            str(role_path),
            "--output",
            str(out_path),
        ]
    )
    assert rc == 0
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["readiness_posture"] == "READY_FOR_SEPARATE_COUNTED_R5_RERUN_LAUNCH_SURFACE_CONSIDERATION"
