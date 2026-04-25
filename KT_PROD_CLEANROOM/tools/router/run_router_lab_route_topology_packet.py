from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.router.run_verified_entrant_lab_scorecard import _load_json_dict, _resolve


def _route_pair_key(adapter_ids: Sequence[Any]) -> str:
    cleaned = [str(item).strip() for item in adapter_ids if str(item).strip()]
    return " -> ".join(cleaned)


def build_router_lab_route_topology_packet(
    *,
    role_report: Dict[str, Any],
    role_report_ref: str,
) -> Dict[str, Any]:
    if str(role_report.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: role-separated report must remain lab-only")

    summary = role_report.get("summary")
    case_rows = role_report.get("case_rows")
    if not isinstance(summary, dict) or not isinstance(case_rows, list):
        raise RuntimeError("FAIL_CLOSED: role-separated report incomplete")

    route_pair_counts: Counter[str] = Counter()
    family_route_pair_counts: Dict[str, Counter[str]] = defaultdict(Counter)
    family_case_counts: Counter[str] = Counter()
    generalist_stage_participation_count = 0
    unique_specialist_sets: Counter[str] = Counter()

    normalized_rows: List[Dict[str, Any]] = []
    for row in case_rows:
        if not isinstance(row, dict):
            continue
        case_id = str(row.get("case_id", "")).strip()
        family = str(row.get("pattern_family", "")).strip() or case_id
        routed_adapter_ids = [str(item).strip() for item in row.get("routed_adapter_ids", []) if str(item).strip()]
        if not routed_adapter_ids:
            continue

        route_pair = _route_pair_key(routed_adapter_ids)
        unique_specialist_set = " + ".join(sorted(set(routed_adapter_ids)))
        route_pair_counts[route_pair] += 1
        family_route_pair_counts[family][route_pair] += 1
        family_case_counts[family] += 1
        unique_specialist_sets[unique_specialist_set] += 1
        if any("generalist" in adapter_id.lower() for adapter_id in routed_adapter_ids):
            generalist_stage_participation_count += 1

        normalized_rows.append(
            {
                "case_id": case_id,
                "pattern_family": family,
                "route_pair": route_pair,
                "unique_specialist_set": unique_specialist_set,
                "route_advantage_delta": float(row.get("route_advantage_delta", 0.0)),
            }
        )

    case_count = len(normalized_rows)
    if case_count == 0:
        raise RuntimeError("FAIL_CLOSED: no route-topology cases available")

    dominant_route_pair, dominant_route_pair_case_count = sorted(
        route_pair_counts.items(),
        key=lambda item: (-item[1], item[0]),
    )[0]
    dominant_route_pair_share = round(dominant_route_pair_case_count / case_count, 6)
    unique_route_pair_count = len(route_pair_counts)
    family_count = len(family_case_counts)
    multi_topology_visible = unique_route_pair_count >= 2
    topology_concentrated = dominant_route_pair_share >= 0.75

    if multi_topology_visible and not topology_concentrated:
        posture = "ROUTE_TOPOLOGY_BROADENING_VISIBLE"
        recommendation = "KEEP_EXPANDING_DISTINCT_SPECIALIST_HANDOFF_PATTERNS"
    else:
        posture = "ROUTE_TOPOLOGY_CONCENTRATED__DIVERSIFY_HANDOFFS"
        recommendation = "DEVELOP_A_SECOND_DISTINCT_SPECIALIST_HANDOFF_PATTERN_BEFORE_ANY_FUTURE_COUNTED_REOPENING"

    family_rows = []
    for family in sorted(family_case_counts):
        family_pairs = family_route_pair_counts[family]
        dominant_family_pair, dominant_family_pair_count = sorted(
            family_pairs.items(),
            key=lambda item: (-item[1], item[0]),
        )[0]
        family_rows.append(
            {
                "pattern_family": family,
                "case_count": int(family_case_counts[family]),
                "unique_route_pair_count": len(family_pairs),
                "dominant_route_pair": dominant_family_pair,
                "dominant_route_pair_case_count": int(dominant_family_pair_count),
                "dominant_route_pair_share": round(dominant_family_pair_count / int(family_case_counts[family]), 6),
            }
        )

    route_pair_rows = [
        {
            "route_pair": route_pair,
            "case_count": count,
            "case_share": round(count / case_count, 6),
        }
        for route_pair, count in sorted(route_pair_counts.items(), key=lambda item: (-item[1], item[0]))
    ]

    return {
        "schema_id": "kt.router_lab_route_topology_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "claim_boundary": (
            "This packet is lab-only and noncanonical. It measures how concentrated or diverse the current "
            "router-shadow handoff topology is, but it is not tournament truth, not R5 evidence, does not earn "
            "router superiority, and cannot unlock R6, lobe authority, externality, comparative claims, or commercial activation."
        ),
        "role_separated_report_ref": role_report_ref,
        "summary": {
            "case_count": case_count,
            "family_count": family_count,
            "unique_route_pair_count": unique_route_pair_count,
            "dominant_route_pair": dominant_route_pair,
            "dominant_route_pair_case_count": dominant_route_pair_case_count,
            "dominant_route_pair_share": dominant_route_pair_share,
            "generalist_stage_participation_count": generalist_stage_participation_count,
            "unique_specialist_set_count": len(unique_specialist_sets),
            "multi_topology_visible": multi_topology_visible,
            "topology_concentrated": topology_concentrated,
        },
        "route_topology_posture": posture,
        "recommendation": recommendation,
        "route_pair_rows": route_pair_rows,
        "family_rows": family_rows,
        "unique_specialist_sets": [
            {
                "specialist_set": key,
                "case_count": count,
            }
            for key, count in sorted(unique_specialist_sets.items(), key=lambda item: (-item[1], item[0]))
        ],
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a lab-only packet that measures route-topology concentration over the current role-separated router-shadow surface."
    )
    parser.add_argument("--role-report", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    role_report_ref = str(args.role_report)
    role_report = _load_json_dict(_resolve(root, role_report_ref), name="role_separated_tie_router_shadow_report")
    packet = build_router_lab_route_topology_packet(
        role_report=role_report,
        role_report_ref=role_report_ref,
    )
    output_path = _resolve(root, str(args.output))
    write_json_stable(output_path, packet)
    print(json.dumps(packet["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
