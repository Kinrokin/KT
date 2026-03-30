from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.router.run_role_separated_tie_router_shadow import (
    DEFAULT_SUITE_REL as ROLE_SEPARATED_SUITE_REL,
    build_role_separated_tie_router_shadow_report,
)
from tools.router.run_verified_entrant_lab_scorecard import _load_json_dict, _resolve


def _git_head(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


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


def _normalize_report(report: Dict[str, Any]) -> Dict[str, Any]:
    case_rows = report.get("case_rows")
    if not isinstance(case_rows, list):
        raise RuntimeError("FAIL_CLOSED: role-separated report case_rows missing")
    return {
        "summary": report.get("summary"),
        "cases": [
            {
                "case_id": str(row.get("case_id", "")).strip(),
                "pattern_family": str(row.get("pattern_family", "")).strip(),
                "route_advantage": bool(row.get("route_advantage", False)),
                "role_separation_enforced": bool(row.get("role_separation_enforced", False)),
                "routed_adapter_ids": list(row.get("routed_adapter_ids", [])),
                "route_advantage_delta": float(row.get("route_advantage_delta", 0.0)),
                "recommended_action": str(row.get("recommended_action", "")).strip(),
            }
            for row in case_rows
            if isinstance(row, dict)
        ],
    }


def _report_preserves_shadow_constraints(report: Dict[str, Any]) -> bool:
    if str(report.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        return False
    claim_boundary = str(report.get("claim_boundary", "")).strip().lower()
    required_terms = ("not r5 evidence", "cannot unlock r6")
    if any(term not in claim_boundary for term in required_terms):
        return False

    summary = report.get("summary")
    case_rows = report.get("case_rows")
    if not isinstance(summary, dict) or not isinstance(case_rows, list):
        raise RuntimeError("FAIL_CLOSED: role-separated report incomplete")

    if int(summary.get("route_advantage_case_count", 0)) != int(summary.get("case_count", 0)):
        return False
    if int(summary.get("role_separated_case_count", 0)) != int(summary.get("case_count", 0)):
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


def _fresh_exposure_assessment(report: Dict[str, Any], fresh_job_dirs: Sequence[Path]) -> Dict[str, Any]:
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

    case_rows = report.get("case_rows")
    if not isinstance(case_rows, list):
        raise RuntimeError("FAIL_CLOSED: role-separated report case_rows missing for fresh assessment")

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
        if isinstance(stage_rows, list) and any(
            isinstance(stage_row, dict) and str(stage_row.get("job_dir", "")).strip() in fresh_paths
            for stage_row in stage_rows
        ):
            fresh_routed_stage_case_ids.append(case_id)

    survives = bool(fresh_baseline_case_ids) and len(fresh_routed_stage_case_ids) == len(case_rows)
    return {
        "fresh_job_dir_count": len(fresh_paths),
        "fresh_job_dirs": sorted(fresh_paths),
        "fresh_baseline_case_count": len(fresh_baseline_case_ids),
        "fresh_baseline_case_ids": fresh_baseline_case_ids,
        "fresh_routed_stage_case_count": len(fresh_routed_stage_case_ids),
        "fresh_routed_stage_case_ids": fresh_routed_stage_case_ids,
        "survives_fresh_verified_entrants": survives,
        "status": (
            "PASS_FRESH_EXPOSURE_CONFIRMED"
            if survives
            else "HOLD_FRESH_EXPOSURE_NOT_YET_CONFIRMED"
        ),
    }


def _tournament_like_assessment(report: Dict[str, Any]) -> Dict[str, Any]:
    summary = report.get("summary")
    case_rows = report.get("case_rows")
    if not isinstance(summary, dict) or not isinstance(case_rows, list):
        raise RuntimeError("FAIL_CLOSED: role-separated report incomplete for tournament-like assessment")

    family_case_counts = summary.get("family_case_counts")
    family_route_advantage_counts = summary.get("family_route_advantage_counts")
    if not isinstance(family_case_counts, dict) or not isinstance(family_route_advantage_counts, dict):
        raise RuntimeError("FAIL_CLOSED: role-separated family summary missing")

    min_delta = min(float(row.get("route_advantage_delta", 0.0)) for row in case_rows if isinstance(row, dict))
    family_count = len(family_case_counts)
    fully_covered_families = all(
        int(family_case_counts.get(family, 0)) == int(family_route_advantage_counts.get(family, 0))
        for family in family_case_counts
    )
    all_keep_and_expand = all(
        isinstance(row, dict) and str(row.get("recommended_action", "")).strip() == "KEEP_AND_EXPAND"
        for row in case_rows
    )
    generalist_routed_stage_count = sum(
        1
        for row in case_rows
        if isinstance(row, dict)
        for adapter_id in row.get("routed_adapter_ids", [])
        if str(adapter_id).strip() == "lobe.generalist.shadow.v1"
    )
    passes = (
        int(summary.get("case_count", 0)) >= 4
        and family_count >= 2
        and fully_covered_families
        and all_keep_and_expand
        and min_delta >= 5.0
        and generalist_routed_stage_count == 0
    )
    return {
        "case_count": int(summary.get("case_count", 0)),
        "family_count": family_count,
        "minimum_route_advantage_delta": min_delta,
        "fully_covered_families": fully_covered_families,
        "all_keep_and_expand": all_keep_and_expand,
        "generalist_routed_stage_count": generalist_routed_stage_count,
        "tournament_like_constraints_passed": passes,
        "status": "PASS_TOURNAMENT_LIKE_THRESHOLD" if passes else "HOLD_TOURNAMENT_LIKE_THRESHOLD_NOT_EARNED",
    }


def build_role_separated_router_survival_packet(
    *,
    root: Path,
    suite: Dict[str, Any],
    suite_ref: str,
    job_dirs: Sequence[Path],
    fresh_job_dirs: Sequence[Path],
) -> Dict[str, Any]:
    canonical_job_dirs = _ordered_unique_paths(job_dirs)
    canonical_fresh_job_dirs = _ordered_unique_paths(fresh_job_dirs)
    if not canonical_job_dirs:
        raise RuntimeError("FAIL_CLOSED: no job dirs supplied for role-separated survival packet")

    head_before = _git_head(root)
    first = build_role_separated_tie_router_shadow_report(
        root=root,
        suite=suite,
        job_dirs=canonical_job_dirs,
        suite_ref=suite_ref,
    )
    second = build_role_separated_tie_router_shadow_report(
        root=root,
        suite=suite,
        job_dirs=canonical_job_dirs,
        suite_ref=suite_ref,
    )
    head_after = _git_head(root)

    reproducible_across_reruns = _normalize_report(first) == _normalize_report(second)
    same_head_lab_consistent = head_before == head_after
    shadow_constraints_preserved = _report_preserves_shadow_constraints(first)
    fresh_assessment = _fresh_exposure_assessment(first, canonical_fresh_job_dirs)
    tournament_like = _tournament_like_assessment(first)

    survives_fresh_verified_entrants = bool(fresh_assessment["survives_fresh_verified_entrants"])
    tournament_like_constraints_passed = bool(tournament_like["tournament_like_constraints_passed"])

    blockers: List[str] = []
    if not reproducible_across_reruns:
        blockers.append("ROLE_SEPARATED_RERUN_REPRODUCIBILITY_NOT_EARNED")
    if not same_head_lab_consistent:
        blockers.append("LAB_HEAD_CHANGED_DURING_ROLE_SEPARATED_PACKET_BUILD")
    if not shadow_constraints_preserved:
        blockers.append("ROLE_SEPARATED_SHADOW_CONSTRAINTS_NOT_PRESERVED")
    if not survives_fresh_verified_entrants:
        blockers.append("ROLE_SEPARATED_FRESH_VERIFIED_ENTRANT_SURVIVAL_NOT_EARNED")
    if not tournament_like_constraints_passed:
        blockers.append("ROLE_SEPARATED_TOURNAMENT_LIKE_THRESHOLD_NOT_EARNED")

    posture = (
        "LAB_ROLE_SEPARATED_SURVIVAL_CONFIRMED"
        if not blockers
        else "HOLD_LAB_ONLY_PENDING_ROLE_SEPARATED_REWORK"
    )

    return {
        "schema_id": "kt.role_separated_router_survival_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "lab_head": head_before,
        "claim_boundary": (
            "This packet is lab-only and noncanonical. It measures whether the role-separated router-shadow "
            "pattern survives reruns, fresh verified entrant exposure, and tournament-like thresholds, but it "
            "is not tournament truth, not R5 evidence, does not earn router superiority, and cannot unlock R6, "
            "lobe authority, externality, comparative claims, or commercial activation."
        ),
        "questions": {
            "reproducible_across_reruns": reproducible_across_reruns,
            "same_head_lab_consistent": same_head_lab_consistent,
            "shadow_constraints_preserved": shadow_constraints_preserved,
            "survives_fresh_verified_entrants": survives_fresh_verified_entrants,
            "tournament_like_constraints_passed": tournament_like_constraints_passed,
        },
        "posture": posture,
        "blockers": blockers,
        "job_dirs": [path.as_posix() for path in canonical_job_dirs],
        "suite_ref": suite_ref,
        "role_separated_summary": first.get("summary"),
        "fresh_verified_entrant_assessment": fresh_assessment,
        "tournament_like_assessment": tournament_like,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a lab-only survival packet over the role-separated router-shadow surface."
    )
    parser.add_argument("--suite", default=ROLE_SEPARATED_SUITE_REL)
    parser.add_argument("--job-dir", action="append", required=True, help="Verified factory job_dir. Repeat for multiple entrants.")
    parser.add_argument(
        "--fresh-job-dir",
        action="append",
        default=[],
        help="Verified entrant job_dir already present in the active cohort that should count as fresh exposure.",
    )
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    suite_ref = str(args.suite)
    suite = _load_json_dict(_resolve(root, suite_ref), name="role_separated_tie_router_shadow_suite")
    job_dirs = [_resolve(root, str(item)) for item in args.job_dir]
    fresh_job_dirs = [_resolve(root, str(item)) for item in args.fresh_job_dir]

    packet = build_role_separated_router_survival_packet(
        root=root,
        suite=suite,
        suite_ref=suite_ref,
        job_dirs=job_dirs,
        fresh_job_dirs=fresh_job_dirs,
    )
    output_path = _resolve(root, str(args.output))
    write_json_stable(output_path, packet)
    print(json.dumps(packet["questions"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
