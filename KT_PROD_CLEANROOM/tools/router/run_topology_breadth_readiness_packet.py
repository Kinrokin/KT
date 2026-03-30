from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.router.run_second_route_topology_confirmation_packet import (
    DEFAULT_SECOND_SUITE_REL,
    build_second_route_topology_confirmation_packet,
)
from tools.router.run_verified_entrant_lab_scorecard import _load_json_dict, _resolve


def _git_head(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return result.stdout.strip()
    return f"NON_GIT_LAB_ROOT::{root.resolve().as_posix()}"


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


def _normalize_confirmation_packet(packet: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "summary": packet.get("summary"),
        "primary_route_pairs": packet.get("primary_route_pairs"),
        "second_route_pairs": packet.get("second_route_pairs"),
        "alternate_route_pairs": packet.get("alternate_route_pairs"),
        "second_report_summary": packet.get("second_report_summary"),
        "second_report_case_rows": packet.get("second_report_case_rows"),
    }


def _shadow_constraints_preserved(packet: Dict[str, Any]) -> bool:
    if str(packet.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        return False
    claim_boundary = str(packet.get("claim_boundary", "")).strip().lower()
    required_terms = ("not r5 evidence", "cannot unlock r6")
    if any(term not in claim_boundary for term in required_terms):
        return False

    summary = packet.get("second_report_summary")
    case_rows = packet.get("second_report_case_rows")
    if not isinstance(summary, dict) or not isinstance(case_rows, list):
        raise RuntimeError("FAIL_CLOSED: second topology confirmation packet incomplete")

    if int(summary.get("route_advantage_case_count", 0)) != int(summary.get("case_count", 0)):
        return False

    for row in case_rows:
        if not isinstance(row, dict):
            continue
        if not bool(row.get("route_advantage", False)):
            return False
        if not bool(row.get("multi_adapter_route", False)):
            return False
        if not bool(row.get("role_separation_enforced", False)):
            return False
    return True


def _fresh_exposure_assessment(packet: Dict[str, Any], fresh_job_dirs: Sequence[Path]) -> Dict[str, Any]:
    fresh_paths = {path.resolve().as_posix() for path in fresh_job_dirs}
    if not fresh_paths:
        return {
            "fresh_job_dir_count": 0,
            "fresh_job_dirs": [],
            "fresh_baseline_case_count": 0,
            "fresh_routed_stage_case_count": 0,
            "survives_fresh_verified_entrants": False,
            "status": "NOT_EVALUATED_NO_FRESH_JOB_DIRS",
        }

    case_rows = packet.get("second_report_case_rows")
    if not isinstance(case_rows, list):
        raise RuntimeError("FAIL_CLOSED: second topology confirmation case rows missing")

    fresh_baseline_case_ids: List[str] = []
    fresh_routed_stage_case_ids: List[str] = []
    for row in case_rows:
        if not isinstance(row, dict):
            continue
        case_id = str(row.get("case_id", "")).strip()
        best_single = row.get("best_single_baseline")
        if isinstance(best_single, dict) and str(best_single.get("job_dir", "")).strip() in fresh_paths:
            fresh_baseline_case_ids.append(case_id)
        stage_rows = row.get("routed_stage_picks")
        if isinstance(stage_rows, list) and all(
            isinstance(stage_row, dict) and str(stage_row.get("job_dir", "")).strip() in fresh_paths
            for stage_row in stage_rows
        ):
            fresh_routed_stage_case_ids.append(case_id)

    case_count = len(case_rows)
    survives = len(fresh_baseline_case_ids) == case_count and len(fresh_routed_stage_case_ids) == case_count
    return {
        "fresh_job_dir_count": len(fresh_paths),
        "fresh_job_dirs": sorted(fresh_paths),
        "fresh_baseline_case_count": len(fresh_baseline_case_ids),
        "fresh_baseline_case_ids": fresh_baseline_case_ids,
        "fresh_routed_stage_case_count": len(fresh_routed_stage_case_ids),
        "fresh_routed_stage_case_ids": fresh_routed_stage_case_ids,
        "survives_fresh_verified_entrants": survives,
        "status": "PASS_FRESH_EXPOSURE_CONFIRMED" if survives else "HOLD_FRESH_EXPOSURE_NOT_YET_CONFIRMED",
    }


def _tournament_like_assessment(packet: Dict[str, Any]) -> Dict[str, Any]:
    summary = packet.get("second_report_summary")
    case_rows = packet.get("second_report_case_rows")
    if not isinstance(summary, dict) or not isinstance(case_rows, list):
        raise RuntimeError("FAIL_CLOSED: second topology confirmation packet incomplete")

    case_count = int(summary.get("case_count", 0))
    family_case_counts: Dict[str, int] = {}
    family_route_advantage_counts: Dict[str, int] = {}
    min_delta = 0.0
    if case_rows:
        min_delta = min(float(row.get("route_advantage_delta", 0.0)) for row in case_rows if isinstance(row, dict))
    all_keep_and_expand = all(
        isinstance(row, dict) and str(row.get("recommended_action", "")).strip() == "KEEP_AND_EXPAND"
        for row in case_rows
    )
    fully_role_separated = all(
        isinstance(row, dict) and bool(row.get("role_separation_enforced", False))
        for row in case_rows
    )
    for row in case_rows:
        if not isinstance(row, dict):
            continue
        family = str(row.get("pattern_family", "")).strip() or str(row.get("case_id", "")).strip()
        family_case_counts[family] = family_case_counts.get(family, 0) + 1
        if bool(row.get("route_advantage", False)):
            family_route_advantage_counts[family] = family_route_advantage_counts.get(family, 0) + 1

    fully_covered_families = all(
        family_case_counts.get(family, 0) == family_route_advantage_counts.get(family, 0)
        for family in family_case_counts
    )
    passes = (
        case_count >= 3
        and len(family_case_counts) >= 1
        and fully_covered_families
        and all_keep_and_expand
        and fully_role_separated
        and min_delta >= 5.0
    )
    return {
        "case_count": case_count,
        "family_count": len(family_case_counts),
        "minimum_route_advantage_delta": min_delta,
        "fully_covered_families": fully_covered_families,
        "all_keep_and_expand": all_keep_and_expand,
        "fully_role_separated": fully_role_separated,
        "tournament_like_constraints_passed": passes,
        "status": "PASS_TOURNAMENT_LIKE_THRESHOLD" if passes else "HOLD_TOURNAMENT_LIKE_THRESHOLD_NOT_EARNED",
    }


def _route_terminals(route_pairs: Sequence[str]) -> List[str]:
    terminals: List[str] = []
    for pair in route_pairs:
        cleaned = [part.strip() for part in str(pair).split("->") if part.strip()]
        if not cleaned:
            continue
        terminal = cleaned[-1]
        if terminal not in terminals:
            terminals.append(terminal)
    return terminals


def build_topology_breadth_readiness_packet(
    *,
    root: Path,
    primary_role_report: Dict[str, Any],
    primary_role_report_ref: str,
    second_suite: Dict[str, Any],
    second_suite_ref: str,
    job_dirs: Sequence[Path],
    fresh_job_dirs: Sequence[Path],
    dominant_route_pair: str,
) -> Dict[str, Any]:
    canonical_job_dirs = _ordered_unique_paths(job_dirs)
    canonical_fresh_job_dirs = _ordered_unique_paths(fresh_job_dirs)
    if not canonical_job_dirs:
        raise RuntimeError("FAIL_CLOSED: no job dirs supplied for topology breadth readiness packet")

    head_before = _git_head(root)
    first = build_second_route_topology_confirmation_packet(
        primary_role_report=primary_role_report,
        primary_role_report_ref=primary_role_report_ref,
        second_suite=second_suite,
        second_suite_ref=second_suite_ref,
        job_dirs=canonical_job_dirs,
        dominant_route_pair=dominant_route_pair,
        root=root,
    )
    second = build_second_route_topology_confirmation_packet(
        primary_role_report=primary_role_report,
        primary_role_report_ref=primary_role_report_ref,
        second_suite=second_suite,
        second_suite_ref=second_suite_ref,
        job_dirs=canonical_job_dirs,
        dominant_route_pair=dominant_route_pair,
        root=root,
    )
    head_after = _git_head(root)

    reproducible_across_reruns = _normalize_confirmation_packet(first) == _normalize_confirmation_packet(second)
    same_head_lab_consistent = head_before == head_after
    shadow_constraints_preserved = _shadow_constraints_preserved(first)
    fresh_assessment = _fresh_exposure_assessment(first, canonical_fresh_job_dirs)
    tournament_like = _tournament_like_assessment(first)

    second_distinct_topology_visible = bool(first.get("summary", {}).get("second_distinct_topology_visible", False))
    primary_route_pairs = [str(item).strip() for item in first.get("primary_route_pairs", []) if str(item).strip()]
    second_route_pairs = [str(item).strip() for item in first.get("second_route_pairs", []) if str(item).strip()]
    combined_route_pairs: List[str] = []
    for pair in primary_route_pairs + second_route_pairs:
        if pair not in combined_route_pairs:
            combined_route_pairs.append(pair)

    primary_terminals = _route_terminals(primary_route_pairs)
    second_terminals = _route_terminals(second_route_pairs)
    combined_terminals = _route_terminals(combined_route_pairs)

    survives_fresh_verified_entrants = bool(fresh_assessment["survives_fresh_verified_entrants"])
    tournament_like_constraints_passed = bool(tournament_like["tournament_like_constraints_passed"])
    downstream_terminal_diversity_earned = len(combined_terminals) >= 2
    not_code_specialist_dependence_in_disguise = downstream_terminal_diversity_earned

    blockers: List[str] = []
    if not reproducible_across_reruns:
        blockers.append("SECOND_TOPOLOGY_RERUN_REPRODUCIBILITY_NOT_EARNED")
    if not same_head_lab_consistent:
        blockers.append("LAB_HEAD_CHANGED_DURING_SECOND_TOPOLOGY_PACKET_BUILD")
    if not shadow_constraints_preserved:
        blockers.append("SECOND_TOPOLOGY_SHADOW_CONSTRAINTS_NOT_PRESERVED")
    if not survives_fresh_verified_entrants:
        blockers.append("SECOND_TOPOLOGY_FRESH_VERIFIED_ENTRANT_SURVIVAL_NOT_EARNED")
    if not tournament_like_constraints_passed:
        blockers.append("SECOND_TOPOLOGY_TOURNAMENT_LIKE_THRESHOLD_NOT_EARNED")
    if not second_distinct_topology_visible:
        blockers.append("SECOND_DISTINCT_ROUTE_TOPOLOGY_NOT_VISIBLE")
    if not downstream_terminal_diversity_earned:
        blockers.append("DOWNSTREAM_TERMINAL_DIVERSITY_NOT_EARNED")

    posture = (
        "READY_FOR_LATER_LAB_READINESS_REFRESH"
        if not blockers
        else "HOLD_LAB_ONLY_PENDING_DOWNSTREAM_DIVERSITY"
    )

    return {
        "schema_id": "kt.topology_breadth_readiness_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "lab_head": head_before,
        "claim_boundary": (
            "This packet is lab-only and noncanonical. It checks whether the second routed topology survives as a broad "
            "lab signal without collapsing into the same downstream specialist bottleneck, but it is not tournament truth, "
            "not R5 evidence, does not earn router superiority, and cannot unlock R6, lobe authority, externality, "
            "comparative claims, or commercial activation."
        ),
        "questions": {
            "reproducible_across_reruns": reproducible_across_reruns,
            "same_head_lab_consistent": same_head_lab_consistent,
            "shadow_constraints_preserved": shadow_constraints_preserved,
            "survives_fresh_verified_entrants": survives_fresh_verified_entrants,
            "tournament_like_constraints_passed": tournament_like_constraints_passed,
            "second_distinct_topology_visible": second_distinct_topology_visible,
            "downstream_terminal_diversity_earned": downstream_terminal_diversity_earned,
            "not_code_specialist_dependence_in_disguise": not_code_specialist_dependence_in_disguise,
        },
        "topology_breadth_posture": posture,
        "blockers": blockers,
        "source_refs": {
            "primary_role_report_ref": primary_role_report_ref,
            "second_suite_ref": second_suite_ref,
        },
        "job_dirs": [path.as_posix() for path in canonical_job_dirs],
        "fresh_job_dirs": [path.as_posix() for path in canonical_fresh_job_dirs],
        "route_topology_summary": {
            "primary_route_pairs": primary_route_pairs,
            "second_route_pairs": second_route_pairs,
            "combined_route_pairs": combined_route_pairs,
            "primary_terminal_adapters": primary_terminals,
            "second_terminal_adapters": second_terminals,
            "combined_terminal_adapters": combined_terminals,
            "combined_unique_route_pair_count": len(combined_route_pairs),
            "combined_unique_terminal_adapter_count": len(combined_terminals),
        },
        "fresh_verified_entrant_assessment": fresh_assessment,
        "tournament_like_assessment": tournament_like,
        "second_topology_summary": first.get("summary"),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a lab-only readiness packet for topology breadth beyond a single dominant routed specialist bottleneck."
    )
    parser.add_argument("--primary-role-report", required=True)
    parser.add_argument("--second-suite", default=DEFAULT_SECOND_SUITE_REL)
    parser.add_argument("--job-dir", action="append", required=True)
    parser.add_argument("--fresh-job-dir", action="append", default=[])
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
    second_suite = _load_json_dict(_resolve(root, second_ref), name="second_topology_suite")
    job_dirs = [_resolve(root, str(item)) for item in args.job_dir]
    fresh_job_dirs = [_resolve(root, str(item)) for item in args.fresh_job_dir]

    packet = build_topology_breadth_readiness_packet(
        root=root,
        primary_role_report=primary_report,
        primary_role_report_ref=primary_ref,
        second_suite=second_suite,
        second_suite_ref=second_ref,
        job_dirs=job_dirs,
        fresh_job_dirs=fresh_job_dirs,
        dominant_route_pair=str(args.dominant_route_pair),
    )
    output_path = _resolve(root, str(args.output))
    write_json_stable(output_path, packet)
    print(json.dumps(packet["questions"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
