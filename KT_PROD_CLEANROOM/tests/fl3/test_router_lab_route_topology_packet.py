from __future__ import annotations

import json
from pathlib import Path

from tools.router.run_router_lab_route_topology_packet import (  # noqa: E402
    build_router_lab_route_topology_packet,
    main,
)


def _role_report(*, route_pairs: list[tuple[str, str, str]]) -> dict:
    case_rows = []
    family_counts: dict[str, int] = {}
    family_route_counts: dict[str, int] = {}
    for case_id, family, route_pair in route_pairs:
        adapter_ids = [part.strip() for part in route_pair.split("->")]
        case_rows.append(
            {
                "case_id": case_id,
                "pattern_family": family,
                "routed_adapter_ids": adapter_ids,
                "route_advantage_delta": 6.0,
            }
        )
        family_counts[family] = family_counts.get(family, 0) + 1
        family_route_counts[family] = family_route_counts.get(family, 0) + 1
    return {
        "schema_id": "kt.role_separated_tie_router_shadow_report.v1",
        "mode": "LAB_ONLY_NONCANONICAL",
        "summary": {
            "case_count": len(case_rows),
            "family_case_counts": family_counts,
            "family_route_advantage_counts": family_route_counts,
            "role_separated_case_count": len(case_rows),
            "route_advantage_case_count": len(case_rows),
        },
        "case_rows": case_rows,
    }


def test_route_topology_packet_flags_single_handoff_dominance() -> None:
    packet = build_router_lab_route_topology_packet(
        role_report=_role_report(
            route_pairs=[
                ("CASE_A", "FAM_A", "math -> code"),
                ("CASE_B", "FAM_A", "math -> code"),
                ("CASE_C", "FAM_B", "math -> code"),
            ]
        ),
        role_report_ref="role.json",
    )

    assert packet["status"] == "PASS"
    assert packet["summary"]["unique_route_pair_count"] == 1
    assert packet["summary"]["dominant_route_pair"] == "math -> code"
    assert packet["summary"]["dominant_route_pair_share"] == 1.0
    assert packet["route_topology_posture"] == "ROUTE_TOPOLOGY_CONCENTRATED__DIVERSIFY_HANDOFFS"


def test_route_topology_packet_can_recognize_broadening() -> None:
    packet = build_router_lab_route_topology_packet(
        role_report=_role_report(
            route_pairs=[
                ("CASE_A", "FAM_A", "math -> code"),
                ("CASE_B", "FAM_A", "math -> code"),
                ("CASE_C", "FAM_B", "research -> writer"),
                ("CASE_D", "FAM_B", "research -> writer"),
            ]
        ),
        role_report_ref="role.json",
    )

    assert packet["status"] == "PASS"
    assert packet["summary"]["unique_route_pair_count"] == 2
    assert packet["summary"]["dominant_route_pair_share"] == 0.5
    assert packet["route_topology_posture"] == "ROUTE_TOPOLOGY_BROADENING_VISIBLE"


def test_route_topology_packet_cli_writes_packet(tmp_path: Path) -> None:
    role_report_path = tmp_path / "role_report.json"
    role_report_path.write_text(
        json.dumps(
            _role_report(
                route_pairs=[
                    ("CASE_A", "FAM_A", "math -> code"),
                    ("CASE_B", "FAM_B", "math -> code"),
                ]
            ),
            indent=2,
        ),
        encoding="utf-8",
    )
    out_path = tmp_path / "route_topology_packet.json"

    rc = main(
        [
            "--role-report",
            str(role_report_path),
            "--output",
            str(out_path),
        ]
    )

    assert rc == 0
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["summary"]["unique_route_pair_count"] == 1
