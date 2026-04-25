from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.router.run_role_separated_tie_router_shadow import (
    build_role_separated_tie_router_shadow_report,
)
from tools.router.run_verified_entrant_lab_scorecard import _load_json_dict, _resolve


DEFAULT_SECOND_SUITE_REL = "KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/ROUTER_LAB/SECOND_ROUTE_TOPOLOGY_SHADOW_SUITE_V1.json"


def _ordered_unique_paths(items: Sequence[Path]) -> List[Path]:
    seen: set[str] = set()
    ordered: List[Path] = []
    for item in items:
        resolved = item.resolve()
        key = resolved.as_posix()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(resolved)
    return ordered


def _distinct_route_pairs(report: Dict[str, Any]) -> List[str]:
    case_rows = report.get("case_rows")
    if not isinstance(case_rows, list):
        raise RuntimeError("FAIL_CLOSED: role-separated report case_rows missing")
    pairs: List[str] = []
    for row in case_rows:
        if not isinstance(row, dict) or not bool(row.get("route_advantage")):
            continue
        adapter_ids = [str(item).strip() for item in row.get("routed_adapter_ids", []) if str(item).strip()]
        pair = " -> ".join(adapter_ids)
        if pair and pair not in pairs:
            pairs.append(pair)
    return pairs


def build_second_route_topology_confirmation_packet(
    *,
    primary_role_report: Dict[str, Any],
    primary_role_report_ref: str,
    second_suite: Dict[str, Any],
    second_suite_ref: str,
    job_dirs: Sequence[Path],
    dominant_route_pair: str,
    root: Path,
) -> Dict[str, Any]:
    if str(primary_role_report.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: primary role-separated report must remain lab-only")

    canonical_job_dirs = _ordered_unique_paths(job_dirs)
    if not canonical_job_dirs:
        raise RuntimeError("FAIL_CLOSED: no job dirs supplied for second route topology packet")

    second_report = build_role_separated_tie_router_shadow_report(
        root=root,
        suite=second_suite,
        job_dirs=canonical_job_dirs,
        suite_ref=second_suite_ref,
    )
    if str(second_report.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: second route topology report must remain lab-only")

    primary_pairs = _distinct_route_pairs(primary_role_report)
    second_pairs = _distinct_route_pairs(second_report)
    alternate_pairs = [pair for pair in second_pairs if pair != dominant_route_pair]

    second_summary = second_report.get("summary")
    if not isinstance(second_summary, dict):
        raise RuntimeError("FAIL_CLOSED: second route topology summary missing")

    route_advantage_case_count = int(second_summary.get("route_advantage_case_count", 0))
    case_count = int(second_summary.get("case_count", 0))
    second_pattern_clean = route_advantage_case_count == case_count and case_count > 0
    second_distinct_topology_visible = second_pattern_clean and bool(alternate_pairs)

    combined_pairs: List[str] = []
    for pair in primary_pairs + second_pairs:
        if pair not in combined_pairs:
            combined_pairs.append(pair)

    posture = (
        "SECOND_DISTINCT_ROUTE_TOPOLOGY_VISIBLE"
        if second_distinct_topology_visible
        else "SECOND_DISTINCT_ROUTE_TOPOLOGY_NOT_YET_EARNED"
    )
    recommendation = (
        "USE_THIS_SECOND_TOPOLOGY_AS_THE_NEXT_LAB_EXPANSION_TARGET"
        if second_distinct_topology_visible
        else "REWORK_THE_SECOND_TOPOLOGY_SUITE_UNTIL_IT_PRODUCES_A_CLEAN_NONDOMINANT_ROUTE_PAIR"
    )

    return {
        "schema_id": "kt.second_route_topology_confirmation_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "claim_boundary": (
            "This packet is lab-only and noncanonical. It checks whether the cohort now supports a second distinct "
            "winning route topology beyond the current dominant handoff, but it is not tournament truth, not R5 evidence, "
            "does not earn router superiority, and cannot unlock R6, lobe authority, externality, comparative claims, or commercial activation."
        ),
        "primary_role_report_ref": primary_role_report_ref,
        "second_suite_ref": second_suite_ref,
        "job_dirs": [path.as_posix() for path in canonical_job_dirs],
        "dominant_route_pair": dominant_route_pair,
        "summary": {
            "primary_unique_route_pair_count": len(primary_pairs),
            "second_unique_route_pair_count": len(second_pairs),
            "combined_unique_route_pair_count": len(combined_pairs),
            "second_case_count": case_count,
            "second_route_advantage_case_count": route_advantage_case_count,
            "alternate_route_pair_count": len(alternate_pairs),
            "second_distinct_topology_visible": second_distinct_topology_visible
        },
        "posture": posture,
        "recommendation": recommendation,
        "primary_route_pairs": primary_pairs,
        "second_route_pairs": second_pairs,
        "alternate_route_pairs": alternate_pairs,
        "second_report_summary": second_summary,
        "second_report_case_rows": second_report.get("case_rows"),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a lab-only confirmation packet for a second distinct winning route topology."
    )
    parser.add_argument("--primary-role-report", required=True)
    parser.add_argument("--second-suite", default=DEFAULT_SECOND_SUITE_REL)
    parser.add_argument("--job-dir", action="append", required=True)
    parser.add_argument("--dominant-route-pair", default="lobe.math.specialist.v1 -> lobe.code.specialist.v1")
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    primary_ref = str(args.primary_role_report)
    second_ref = str(args.second_suite)
    primary_report = _load_json_dict(_resolve(root, primary_ref), name="primary_role_report")
    second_suite = _load_json_dict(_resolve(root, second_ref), name="second_route_topology_suite")
    job_dirs = [_resolve(root, str(item)) for item in args.job_dir]

    packet = build_second_route_topology_confirmation_packet(
        primary_role_report=primary_report,
        primary_role_report_ref=primary_ref,
        second_suite=second_suite,
        second_suite_ref=second_ref,
        job_dirs=job_dirs,
        dominant_route_pair=str(args.dominant_route_pair),
        root=root,
    )
    output_path = _resolve(root, str(args.output))
    write_json_stable(output_path, packet)
    print(json.dumps(packet["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
