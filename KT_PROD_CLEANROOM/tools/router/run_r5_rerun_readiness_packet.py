from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
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


def _normalize_scorecard(report: Dict[str, Any]) -> Dict[str, Any]:
    case_rows = report.get("case_rows")
    if not isinstance(case_rows, list):
        raise RuntimeError("FAIL_CLOSED: scorecard report case_rows missing")
    return {
        "summary": report.get("summary"),
        "cases": [
            {
                "case_id": str(row.get("case_id", "")).strip(),
                "tie": bool(row.get("tie", False)),
                "winner_adapter_ids": list(row.get("winner_adapter_ids", [])),
                "winning_score": float(row.get("winning_score", 0.0)),
            }
            for row in case_rows
            if isinstance(row, dict)
        ],
    }


def _normalize_tie_report(report: Dict[str, Any]) -> Dict[str, Any]:
    case_rows = report.get("case_rows")
    if not isinstance(case_rows, list):
        raise RuntimeError("FAIL_CLOSED: tie router report case_rows missing")
    return {
        "summary": report.get("summary"),
        "cases": [
            {
                "case_id": str(row.get("case_id", "")).strip(),
                "pattern_family": str(row.get("pattern_family", "")).strip(),
                "route_advantage": bool(row.get("route_advantage", False)),
                "multi_adapter_route": bool(row.get("multi_adapter_route", False)),
                "same_adapter_recombination_only": bool(row.get("same_adapter_recombination_only", False)),
                "recommended_action": str(row.get("recommended_action", "")).strip(),
                "routed_adapter_ids": list(row.get("routed_adapter_ids", [])),
            }
            for row in case_rows
            if isinstance(row, dict)
        ],
    }


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
            job_dirs=job_dirs,
            suite_ref=scorecard_suite_ref,
        ),
        "tie_router": build_verified_tie_router_shadow_report(
            root=root,
            suite=tie_suite,
            job_dirs=job_dirs,
            suite_ref=tie_suite_ref,
        ),
    }


def _tie_report_has_no_family_ambiguity(report: Dict[str, Any]) -> bool:
    summary = report.get("summary")
    if not isinstance(summary, dict):
        raise RuntimeError("FAIL_CLOSED: tie router report summary missing")
    family_case_counts = summary.get("family_case_counts")
    family_route_advantage_counts = summary.get("family_route_advantage_counts")
    if not isinstance(family_case_counts, dict) or not isinstance(family_route_advantage_counts, dict):
        raise RuntimeError("FAIL_CLOSED: tie router family summary missing")
    if int(summary.get("staged_recombination_case_count", 0)) != 0:
        return False
    if int(summary.get("drop_or_rework_case_count", 0)) != 0:
        return False
    for family, raw_count in family_case_counts.items():
        if int(raw_count) != int(family_route_advantage_counts.get(family, 0)):
            return False
    return True


def _tie_report_preserves_shadow_constraints(report: Dict[str, Any]) -> bool:
    if str(report.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        return False
    claim_boundary = str(report.get("claim_boundary", "")).strip().lower()
    required_terms = ("not r5 evidence", "cannot unlock r6")
    if any(term not in claim_boundary for term in required_terms):
        return False

    summary = report.get("summary")
    case_rows = report.get("case_rows")
    if not isinstance(summary, dict) or not isinstance(case_rows, list):
        raise RuntimeError("FAIL_CLOSED: tie router report incomplete")
    if int(summary.get("staged_recombination_case_count", 0)) != 0:
        return False
    if int(summary.get("drop_or_rework_case_count", 0)) != 0:
        return False

    for row in case_rows:
        if not isinstance(row, dict):
            continue
        if not bool(row.get("route_advantage", False)):
            return False
        if not bool(row.get("multi_adapter_route", False)):
            return False
        if bool(row.get("same_adapter_recombination_only", False)):
            return False
    return True


def _supports_fresh_survival(report: Dict[str, Any]) -> bool:
    return _tie_report_preserves_shadow_constraints(report) and _tie_report_has_no_family_ambiguity(report)


def build_r5_rerun_readiness_packet(
    *,
    root: Path,
    scorecard_suite: Dict[str, Any],
    tie_suite: Dict[str, Any],
    scorecard_suite_ref: str,
    tie_suite_ref: str,
    job_dirs: Sequence[Path],
    fresh_job_dirs: Sequence[Path],
) -> Dict[str, Any]:
    canonical_job_dirs = _ordered_unique_paths(job_dirs)
    canonical_fresh_job_dirs = _ordered_unique_paths(fresh_job_dirs)
    if not canonical_job_dirs:
        raise RuntimeError("FAIL_CLOSED: no verified entrant job dirs supplied")

    head_before = _git_head(root)
    first = _build_lab_reports(
        root=root,
        scorecard_suite=scorecard_suite,
        tie_suite=tie_suite,
        scorecard_suite_ref=scorecard_suite_ref,
        tie_suite_ref=tie_suite_ref,
        job_dirs=canonical_job_dirs,
    )
    second = _build_lab_reports(
        root=root,
        scorecard_suite=scorecard_suite,
        tie_suite=tie_suite,
        scorecard_suite_ref=scorecard_suite_ref,
        tie_suite_ref=tie_suite_ref,
        job_dirs=canonical_job_dirs,
    )
    head_after = _git_head(root)

    reproducible_across_reruns = (
        _normalize_scorecard(first["scorecard"]) == _normalize_scorecard(second["scorecard"])
        and _normalize_tie_report(first["tie_router"]) == _normalize_tie_report(second["tie_router"])
    )
    same_head_lab_consistent = head_before == head_after
    shadow_constraints_preserved = _tie_report_preserves_shadow_constraints(first["tie_router"])
    remaining_tie_family_ambiguity = not _tie_report_has_no_family_ambiguity(first["tie_router"])

    fresh_assessment: Dict[str, Any] = {
        "fresh_job_dir_count": len(canonical_fresh_job_dirs),
        "survives_fresh_verified_entrants": False,
        "status": "NOT_EVALUATED_NO_FRESH_JOB_DIRS",
    }
    if canonical_fresh_job_dirs:
        combined_job_dirs = _ordered_unique_paths([*canonical_job_dirs, *canonical_fresh_job_dirs])
        fresh_reports = _build_lab_reports(
            root=root,
            scorecard_suite=scorecard_suite,
            tie_suite=tie_suite,
            scorecard_suite_ref=scorecard_suite_ref,
            tie_suite_ref=tie_suite_ref,
            job_dirs=combined_job_dirs,
        )
        survives_fresh_verified_entrants = _supports_fresh_survival(fresh_reports["tie_router"])
        fresh_assessment = {
            "fresh_job_dir_count": len(canonical_fresh_job_dirs),
            "fresh_job_dirs": [path.as_posix() for path in canonical_fresh_job_dirs],
            "survives_fresh_verified_entrants": survives_fresh_verified_entrants,
            "status": (
                "PASS_FRESH_ENTRANTS_SURVIVE"
                if survives_fresh_verified_entrants
                else "HOLD_FRESH_ENTRANT_SURVIVAL_NOT_EARNED"
            ),
            "scorecard_summary": fresh_reports["scorecard"].get("summary"),
            "tie_router_summary": fresh_reports["tie_router"].get("summary"),
        }
    survives_fresh_verified_entrants = bool(fresh_assessment["survives_fresh_verified_entrants"])

    blockers: List[str] = []
    if not reproducible_across_reruns:
        blockers.append("LAB_RERUN_REPRODUCIBILITY_NOT_EARNED")
    if not same_head_lab_consistent:
        blockers.append("LAB_HEAD_CHANGED_DURING_PACKET_BUILD")
    if not shadow_constraints_preserved:
        blockers.append("LAB_SHADOW_CONSTRAINTS_NOT_PRESERVED")
    if remaining_tie_family_ambiguity:
        blockers.append("TIE_FAMILY_AMBIGUITY_REMAINS")
    if not survives_fresh_verified_entrants:
        blockers.append("FRESH_VERIFIED_ENTRANT_SURVIVAL_NOT_YET_CONFIRMED")

    readiness_posture = (
        "READY_FOR_COUNTED_R5_RERUN_CONSIDERATION"
        if not blockers
        else "HOLD_LAB_ONLY_PENDING_ADDITIONAL_CONFIRMATION"
    )

    return {
        "schema_id": "kt.r5_rerun_readiness_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "lab_head": head_before,
        "claim_boundary": (
            "This packet is lab-only and noncanonical. It assesses whether lab evidence is stable enough "
            "to plan a future counted same-head R5 rerun, but it is not R5 evidence, does not earn router "
            "superiority, and cannot unlock R6, lobe authority, externality, comparative claims, or commercial activation."
        ),
        "questions": {
            "reproducible_across_reruns": reproducible_across_reruns,
            "same_head_lab_consistent": same_head_lab_consistent,
            "survives_fresh_verified_entrants": survives_fresh_verified_entrants,
            "shadow_constraints_preserved": shadow_constraints_preserved,
            "remaining_tie_family_ambiguity": remaining_tie_family_ambiguity,
        },
        "readiness_posture": readiness_posture,
        "counted_lane_recommendation": (
            "DO_NOT_OPEN_COUNTED_R5_RERUN_YET"
            if blockers
            else "COUNTED_R5_RERUN_CAN_BE_CONSIDERED_SEPARATELY"
        ),
        "blockers": blockers,
        "baseline_job_dirs": [path.as_posix() for path in canonical_job_dirs],
        "suite_refs": {
            "scorecard_suite_ref": scorecard_suite_ref,
            "tie_suite_ref": tie_suite_ref,
        },
        "lab_signal_summaries": {
            "scorecard_summary": first["scorecard"].get("summary"),
            "tie_router_summary": first["tie_router"].get("summary"),
        },
        "fresh_verified_entrant_assessment": fresh_assessment,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a lab-only readiness packet for planning a future same-head counted R5 rerun."
    )
    parser.add_argument("--scorecard-suite", default=SCORECARD_SUITE_REL)
    parser.add_argument("--tie-suite", default=TIE_SUITE_REL)
    parser.add_argument("--job-dir", action="append", required=True, help="Verified factory job_dir. Repeat for multiple entrants.")
    parser.add_argument("--fresh-job-dir", action="append", default=[], help="Optional fresh verified entrant job_dir for survival confirmation.")
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
    job_dirs = [_resolve(root, str(item)) for item in args.job_dir]
    fresh_job_dirs = [_resolve(root, str(item)) for item in args.fresh_job_dir]

    packet = build_r5_rerun_readiness_packet(
        root=root,
        scorecard_suite=scorecard_suite,
        tie_suite=tie_suite,
        scorecard_suite_ref=scorecard_suite_ref,
        tie_suite_ref=tie_suite_ref,
        job_dirs=job_dirs,
        fresh_job_dirs=fresh_job_dirs,
    )
    output_path = _resolve(root, str(args.output))
    write_json_stable(output_path, packet)
    print(json.dumps(packet["questions"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
