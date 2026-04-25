from __future__ import annotations

import json
from pathlib import Path

from tools.router.run_post_fourth_rerun_fifth_terminal_candidate_packet import (  # noqa: E402
    build_post_fourth_rerun_fifth_terminal_candidate_packet,
    main,
)


def _current_state_overlay() -> dict:
    return {
        "schema_id": "kt.current_campaign_state_overlay.v1",
        "next_counted_workstream_id": "B04_R6_LEARNED_ROUTER_AUTHORIZATION",
        "repo_state_executable_now": False,
        "current_lawful_gate_standing": {
            "inter_gate_state": "GATE_D_POST_FOURTH_RERUN_STATIC_HOLD__COUNTED_LANE_CLOSED",
        },
    }


def _material_change_target_packet() -> dict:
    return {
        "schema_id": "kt.post_fourth_rerun_material_change_target_packet.v1",
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "questions": {
            "router_branch_selected": True,
            "pivot_branch_available": False,
            "requires_new_terminal_adapter_beyond_current_four": True,
        },
        "current_router_hold_summary": {
            "frozen_four_terminal_lab_head": "HEAD_FOUR",
            "frozen_terminal_adapters": [
                "lobe.code.specialist.v1",
                "lobe.writer.specialist.v1",
                "lobe.math.specialist.v1",
                "lobe.research.specialist.v1",
            ],
        },
    }


def _lobe_role_registry() -> dict:
    return {
        "schema_id": "kt.governance.lobe_role_registry.v1",
        "status": "ACTIVE",
        "entries": [
            {"lobe_id": "lobe.auditor.v1", "role": "governance_audit", "status": "RATIFIED_ROUTER_BASELINE"},
            {"lobe_id": "lobe.censor.v1", "role": "safety_enforcer", "status": "RATIFIED_REQUIRED_GUARD"},
            {"lobe_id": "lobe.muse.v1", "role": "creative_generation", "status": "RATIFIED_ROUTER_BASELINE"},
            {"lobe_id": "lobe.quant.v1", "role": "quantitative_reasoning", "status": "RATIFIED_ROUTER_BASELINE"},
            {"lobe_id": "lobe.strategist.v1", "role": "default_generalist", "status": "RATIFIED_ROUTER_BASELINE"},
        ],
    }


def _lobe_cooperation_matrix() -> dict:
    return {
        "schema_id": "kt.lobe_cooperation_matrix.v1",
        "status": "ACTIVE",
        "rows": [
            {
                "primary_lobe": "lobe.auditor.v1",
                "paired_with": ["lobe.censor.v1"],
                "relationship": "required_guard",
            },
            {
                "primary_lobe": "lobe.quant.v1",
                "paired_with": ["lobe.censor.v1"],
                "relationship": "required_guard",
            },
        ],
    }


def _routing_delta_matrix() -> dict:
    return {
        "schema_id": "kt.routing_delta_matrix.v1",
        "status": "ACTIVE",
        "rows": [
            {
                "case_id": "R01",
                "expected_adapter_ids": ["lobe.censor.v1", "lobe.quant.v1"],
                "expected_domain_tag": "math",
            },
            {
                "case_id": "R02",
                "expected_adapter_ids": ["lobe.muse.v1"],
                "expected_domain_tag": "poetry",
            },
            {
                "case_id": "R03",
                "expected_adapter_ids": ["lobe.auditor.v1", "lobe.censor.v1"],
                "expected_domain_tag": "governance",
            },
            {
                "case_id": "R04",
                "expected_adapter_ids": ["lobe.strategist.v1"],
                "expected_domain_tag": "default",
            },
        ],
    }


def test_post_fourth_rerun_fifth_terminal_candidate_packet_selects_auditor() -> None:
    packet = build_post_fourth_rerun_fifth_terminal_candidate_packet(
        current_state_overlay=_current_state_overlay(),
        material_change_target_packet=_material_change_target_packet(),
        lobe_role_registry=_lobe_role_registry(),
        lobe_cooperation_matrix=_lobe_cooperation_matrix(),
        routing_delta_matrix=_routing_delta_matrix(),
        current_state_overlay_ref="overlay.json",
        material_change_target_packet_ref="target.json",
        lobe_role_registry_ref="roles.json",
        lobe_cooperation_matrix_ref="coop.json",
        routing_delta_matrix_ref="routing.json",
    )

    assert packet["status"] == "PASS"
    assert packet["primary_candidate"]["adapter_id"] == "lobe.auditor.v1"
    assert packet["primary_candidate"]["recommended_route_pattern"] == "lobe.censor.v1 -> lobe.auditor.v1"
    assert packet["primary_candidate"]["recommended_suite_ref"].endswith(
        "DOWNSTREAM_DIVERSITY_AUDIT_TERMINAL_SUITE_V1.json"
    )
    assert packet["questions"]["primary_candidate_preserves_existing_guard_semantics"] is True
    assert "lobe.censor.v1" in {item["adapter_id"] for item in packet["blocked_candidates"]}


def test_post_fourth_rerun_fifth_terminal_candidate_packet_blocks_generalist_overlap() -> None:
    packet = build_post_fourth_rerun_fifth_terminal_candidate_packet(
        current_state_overlay=_current_state_overlay(),
        material_change_target_packet=_material_change_target_packet(),
        lobe_role_registry=_lobe_role_registry(),
        lobe_cooperation_matrix=_lobe_cooperation_matrix(),
        routing_delta_matrix=_routing_delta_matrix(),
        current_state_overlay_ref="overlay.json",
        material_change_target_packet_ref="target.json",
        lobe_role_registry_ref="roles.json",
        lobe_cooperation_matrix_ref="coop.json",
        routing_delta_matrix_ref="routing.json",
    )

    blocked = {item["adapter_id"]: item["blocker"] for item in packet["blocked_candidates"]}
    assert blocked["lobe.strategist.v1"] == "DEFAULT_GENERALIST_OVERLAP__NOT_NEW_TERMINAL_BREADTH"
    assert packet["secondary_candidates"][0]["adapter_id"] == "lobe.muse.v1"


def test_post_fourth_rerun_fifth_terminal_candidate_packet_cli_writes_packet(tmp_path: Path) -> None:
    overlay_path = tmp_path / "overlay.json"
    target_path = tmp_path / "target.json"
    roles_path = tmp_path / "roles.json"
    coop_path = tmp_path / "coop.json"
    routing_path = tmp_path / "routing.json"
    out_path = tmp_path / "candidate.json"

    overlay_path.write_text(json.dumps(_current_state_overlay(), indent=2), encoding="utf-8")
    target_path.write_text(json.dumps(_material_change_target_packet(), indent=2), encoding="utf-8")
    roles_path.write_text(json.dumps(_lobe_role_registry(), indent=2), encoding="utf-8")
    coop_path.write_text(json.dumps(_lobe_cooperation_matrix(), indent=2), encoding="utf-8")
    routing_path.write_text(json.dumps(_routing_delta_matrix(), indent=2), encoding="utf-8")

    rc = main(
        [
            "--current-state-overlay",
            str(overlay_path),
            "--material-change-target-packet",
            str(target_path),
            "--lobe-role-registry",
            str(roles_path),
            "--lobe-cooperation-matrix",
            str(coop_path),
            "--routing-delta-matrix",
            str(routing_path),
            "--output",
            str(out_path),
        ]
    )

    assert rc == 0
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["primary_candidate"]["adapter_id"] == "lobe.auditor.v1"
