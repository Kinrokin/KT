from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.router.run_r5_rerun_readiness_packet import (
    _tie_report_has_no_family_ambiguity,
    _tie_report_preserves_shadow_constraints,
)
from tools.router.run_verified_entrant_lab_scorecard import (
    DEFAULT_SUITE_REL as SCORECARD_SUITE_REL,
    _load_json_dict,
    _resolve,
    build_verified_entrant_lab_scorecard,
)
from tools.router.run_verified_tie_router_shadow import (
    DEFAULT_SUITE_REL as TIE_SUITE_REL,
    build_verified_tie_router_shadow_report,
)


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


def _build_lab_reports(
    *,
    root: Path,
    scorecard_suite: Dict[str, Any],
    tie_suite: Dict[str, Any],
    scorecard_suite_ref: str,
    tie_suite_ref: str,
    job_dirs: Sequence[Path],
) -> Dict[str, Any]:
    return {
        "scorecard": build_verified_entrant_lab_scorecard(
            root=root,
            suite=scorecard_suite,
            suite_ref=scorecard_suite_ref,
            job_dirs=job_dirs,
        ),
        "tie_router": build_verified_tie_router_shadow_report(
            root=root,
            suite=tie_suite,
            suite_ref=tie_suite_ref,
            job_dirs=job_dirs,
        ),
    }


def build_router_lab_cohort_stability_packet(
    *,
    root: Path,
    scorecard_suite: Dict[str, Any],
    tie_suite: Dict[str, Any],
    scorecard_suite_ref: str,
    tie_suite_ref: str,
    baseline_job_dirs: Sequence[Path],
    expanded_job_dirs: Sequence[Path],
) -> Dict[str, Any]:
    baseline = _ordered_unique_paths(baseline_job_dirs)
    expanded = _ordered_unique_paths(expanded_job_dirs)
    if not baseline:
        raise RuntimeError("FAIL_CLOSED: baseline cohort missing")
    if not expanded:
        raise RuntimeError("FAIL_CLOSED: expanded cohort missing")
    if len(expanded) < len(baseline):
        raise RuntimeError("FAIL_CLOSED: expanded cohort cannot be smaller than baseline cohort")

    head_before = _git_head(root)
    baseline_reports = _build_lab_reports(
        root=root,
        scorecard_suite=scorecard_suite,
        tie_suite=tie_suite,
        scorecard_suite_ref=scorecard_suite_ref,
        tie_suite_ref=tie_suite_ref,
        job_dirs=baseline,
    )
    expanded_reports = _build_lab_reports(
        root=root,
        scorecard_suite=scorecard_suite,
        tie_suite=tie_suite,
        scorecard_suite_ref=scorecard_suite_ref,
        tie_suite_ref=tie_suite_ref,
        job_dirs=expanded,
    )
    head_after = _git_head(root)

    baseline_scorecard_summary = baseline_reports["scorecard"].get("summary", {})
    expanded_scorecard_summary = expanded_reports["scorecard"].get("summary", {})
    baseline_tie_summary = baseline_reports["tie_router"].get("summary", {})
    expanded_tie_summary = expanded_reports["tie_router"].get("summary", {})

    same_head_lab_consistent = head_before == head_after
    shadow_constraints_preserved_in_all_cohorts = (
        _tie_report_preserves_shadow_constraints(baseline_reports["tie_router"])
        and _tie_report_preserves_shadow_constraints(expanded_reports["tie_router"])
    )
    tie_family_coverage_retained_across_cohorts = (
        _tie_report_has_no_family_ambiguity(baseline_reports["tie_router"])
        and _tie_report_has_no_family_ambiguity(expanded_reports["tie_router"])
    )
    route_advantage_not_weaker_in_expanded_cohort = int(expanded_tie_summary.get("route_advantage_case_count", 0)) >= int(
        baseline_tie_summary.get("route_advantage_case_count", 0)
    )
    differentiated_scorecard_not_weaker_in_expanded_cohort = int(
        expanded_scorecard_summary.get("differentiated_case_count", 0)
    ) >= int(baseline_scorecard_summary.get("differentiated_case_count", 0))

    blockers: List[str] = []
    if not same_head_lab_consistent:
        blockers.append("LAB_HEAD_CHANGED_DURING_COHORT_PACKET_BUILD")
    if not shadow_constraints_preserved_in_all_cohorts:
        blockers.append("SHADOW_CONSTRAINTS_NOT_PRESERVED_IN_ALL_COHORTS")
    if not tie_family_coverage_retained_across_cohorts:
        blockers.append("TIE_FAMILY_ROUTE_ADVANTAGE_NOT_RETAINED_ACROSS_COHORTS")
    if not route_advantage_not_weaker_in_expanded_cohort:
        blockers.append("ROUTE_ADVANTAGE_WEAKENED_IN_EXPANDED_COHORT")
    if not differentiated_scorecard_not_weaker_in_expanded_cohort:
        blockers.append("DIFFERENTIATED_SCORECARD_WEAKENED_IN_EXPANDED_COHORT")

    stability_posture = (
        "LAB_COHORT_STABILITY_CONFIRMED"
        if not blockers
        else "HOLD_LAB_ONLY_PENDING_COHORT_REWORK"
    )

    return {
        "schema_id": "kt.router_lab_cohort_stability_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "lab_head": head_before,
        "claim_boundary": (
            "This packet is lab-only and noncanonical. It measures whether verified-entrant router-shadow "
            "route-advantage patterns remain stable as the cohort expands, but it is not R5 evidence, does not "
            "earn router superiority, and cannot unlock R6, lobe authority, externality, comparative claims, or commercial activation."
        ),
        "questions": {
            "same_head_lab_consistent": same_head_lab_consistent,
            "shadow_constraints_preserved_in_all_cohorts": shadow_constraints_preserved_in_all_cohorts,
            "tie_family_coverage_retained_across_cohorts": tie_family_coverage_retained_across_cohorts,
            "route_advantage_not_weaker_in_expanded_cohort": route_advantage_not_weaker_in_expanded_cohort,
            "differentiated_scorecard_not_weaker_in_expanded_cohort": differentiated_scorecard_not_weaker_in_expanded_cohort,
        },
        "stability_posture": stability_posture,
        "blockers": blockers,
        "cohorts": {
            "baseline": {
                "job_dirs": [path.as_posix() for path in baseline],
                "scorecard_summary": baseline_scorecard_summary,
                "tie_router_summary": baseline_tie_summary,
            },
            "expanded": {
                "job_dirs": [path.as_posix() for path in expanded],
                "scorecard_summary": expanded_scorecard_summary,
                "tie_router_summary": expanded_tie_summary,
            },
        },
        "recommendation": (
            "KEEP_LAB_LOOP_AND_BROADEN_SPECIALIST_COHORTS"
            if not blockers
            else "HOLD_AND_REWORK_LAB_COHORT_SIGNAL"
        ),
        "suite_refs": {
            "scorecard_suite_ref": scorecard_suite_ref,
            "tie_suite_ref": tie_suite_ref,
        },
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a lab-only cohort-stability packet over verified-entrant router-shadow evidence."
    )
    parser.add_argument("--scorecard-suite", default=SCORECARD_SUITE_REL)
    parser.add_argument("--tie-suite", default=TIE_SUITE_REL)
    parser.add_argument("--baseline-job-dir", action="append", required=True)
    parser.add_argument("--expanded-job-dir", action="append", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    scorecard_suite_ref = str(args.scorecard_suite)
    tie_suite_ref = str(args.tie_suite)
    scorecard_suite = _load_json_dict(_resolve(root, scorecard_suite_ref), name="verified_entrant_lab_suite")
    tie_suite = _load_json_dict(_resolve(root, tie_suite_ref), name="verified_tie_router_shadow_suite")
    baseline_job_dirs = [_resolve(root, str(item)) for item in args.baseline_job_dir]
    expanded_job_dirs = [_resolve(root, str(item)) for item in args.expanded_job_dir]

    packet = build_router_lab_cohort_stability_packet(
        root=root,
        scorecard_suite=scorecard_suite,
        tie_suite=tie_suite,
        scorecard_suite_ref=scorecard_suite_ref,
        tie_suite_ref=tie_suite_ref,
        baseline_job_dirs=baseline_job_dirs,
        expanded_job_dirs=expanded_job_dirs,
    )
    output_path = _resolve(root, str(args.output))
    write_json_stable(output_path, packet)
    print(json.dumps(packet["questions"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
