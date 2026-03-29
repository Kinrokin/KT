from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.router.run_verified_entrant_lab_scorecard import (
    _load_json_dict,
    _load_policy_bundles,
    _resolve,
    _score_bundle_for_case,
)


DEFAULT_SUITE_REL = "KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/ROUTER_LAB/VERIFIED_TIE_ROUTER_SHADOW_SUITE_V1.json"


def _best_single_case(*, entrants: Sequence[Dict[str, Any]], case: Dict[str, Any]) -> Dict[str, Any]:
    best_row: Optional[Dict[str, Any]] = None
    for entrant in entrants:
        candidate = max(
            (_score_bundle_for_case(bundle=bundle, case=case) for bundle in entrant["bundles"]),
            key=lambda row: (float(row["score"]), str(row["bundle_id"])),
        )
        row = {
            "adapter_id": entrant["adapter_id"],
            "adapter_version": entrant["adapter_version"],
            "bundle_id": candidate["bundle_id"],
            "genotype": candidate["genotype"],
            "job_dir": entrant["job_dir"],
            "score": candidate["score"],
        }
        if best_row is None or (float(row["score"]), row["bundle_id"]) > (float(best_row["score"]), best_row["bundle_id"]):
            best_row = row
    if best_row is None:
        raise RuntimeError("FAIL_CLOSED: no single-case baseline could be scored")
    return best_row


def _best_stage_pick(*, entrants: Sequence[Dict[str, Any]], stage: Dict[str, Any]) -> Dict[str, Any]:
    best_row: Optional[Dict[str, Any]] = None
    for entrant in entrants:
        candidate = max(
            (_score_bundle_for_case(bundle=bundle, case=stage) for bundle in entrant["bundles"]),
            key=lambda row: (float(row["score"]), str(row["bundle_id"])),
        )
        row = {
            "adapter_id": entrant["adapter_id"],
            "adapter_version": entrant["adapter_version"],
            "bundle_id": candidate["bundle_id"],
            "covered_terms": candidate["covered_terms"],
            "genotype": candidate["genotype"],
            "job_dir": entrant["job_dir"],
            "output_preview": candidate["output_preview"],
            "score": candidate["score"],
            "stage_id": str(stage.get("stage_id", "")).strip(),
        }
        if best_row is None or (float(row["score"]), row["bundle_id"]) > (float(best_row["score"]), best_row["bundle_id"]):
            best_row = row
    if best_row is None:
        raise RuntimeError("FAIL_CLOSED: no stage pick could be scored")
    return best_row


def build_verified_tie_router_shadow_report(
    *,
    root: Path,
    suite: Dict[str, Any],
    job_dirs: Sequence[Path],
    suite_ref: str = DEFAULT_SUITE_REL,
) -> Dict[str, Any]:
    cases = suite.get("cases")
    if not isinstance(cases, list) or not cases:
        raise RuntimeError("FAIL_CLOSED: tie router shadow suite cases missing")

    entrants: List[Dict[str, Any]] = []
    for raw_job_dir in job_dirs:
        job_dir = raw_job_dir.resolve()
        job = _load_json_dict(job_dir / "job.json", name="job")
        bundles = _load_policy_bundles(root=root, job_dir=job_dir)
        entrants.append(
            {
                "adapter_id": str(job.get("adapter_id", "")).strip(),
                "adapter_version": str(job.get("adapter_version", "")).strip(),
                "job_dir": job_dir.as_posix(),
                "job_id": str(job.get("job_id", "")).strip(),
                "bundles": bundles,
            }
        )
    if not entrants:
        raise RuntimeError("FAIL_CLOSED: no verified entrant job dirs supplied")

    case_rows: List[Dict[str, Any]] = []
    route_advantage_case_count = 0
    staged_recombination_case_count = 0
    drop_or_rework_case_count = 0
    for case in cases:
        if not isinstance(case, dict):
            continue
        case_id = str(case.get("case_id", "")).strip()
        if not case_id:
            raise RuntimeError("FAIL_CLOSED: tie router shadow case missing case_id")
        baseline_case = case.get("single_case_baseline")
        if not isinstance(baseline_case, dict):
            raise RuntimeError(f"FAIL_CLOSED: {case_id} missing single_case_baseline")
        stages = case.get("stages")
        if not isinstance(stages, list) or not stages:
            raise RuntimeError(f"FAIL_CLOSED: {case_id} missing stages")

        best_single = _best_single_case(entrants=entrants, case=baseline_case)
        stage_rows = [_best_stage_pick(entrants=entrants, stage=stage) for stage in stages if isinstance(stage, dict)]
        if not stage_rows:
            raise RuntimeError(f"FAIL_CLOSED: {case_id} had no valid stages")

        routed_score = round(sum(float(row["score"]) for row in stage_rows), 6)
        best_single_score = round(float(best_single["score"]), 6)
        routed_adapter_ids = [str(row["adapter_id"]) for row in stage_rows]
        multi_adapter_route = len(set(routed_adapter_ids)) > 1
        route_advantage = routed_score > best_single_score and multi_adapter_route
        same_adapter_recombination_only = routed_score > best_single_score and not multi_adapter_route
        if route_advantage:
            route_advantage_case_count += 1
        if same_adapter_recombination_only:
            staged_recombination_case_count += 1
            drop_or_rework_case_count += 1

        recommended_action = "KEEP_AND_EXPAND" if route_advantage else ("DROP_OR_REWORK" if same_adapter_recombination_only else "HOLD")

        case_rows.append(
            {
                "case_id": case_id,
                "notes": str(case.get("notes", "")).strip(),
                "best_single_baseline": best_single,
                "routed_stage_picks": stage_rows,
                "routed_adapter_ids": routed_adapter_ids,
                "routed_score": routed_score,
                "best_single_score": best_single_score,
                "multi_adapter_route": multi_adapter_route,
                "route_advantage": route_advantage,
                "route_advantage_delta": round(routed_score - best_single_score, 6),
                "recommended_action": recommended_action,
                "same_adapter_recombination_only": same_adapter_recombination_only,
            }
        )

    return {
        "schema_id": "kt.verified_tie_router_shadow_report.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "suite_ref": str(suite_ref),
        "claim_boundary": (
            "This report is lab-only. It measures staged router-shadow opportunity over live verified entrants "
            "for tie cases, but it is not tournament truth, not router superiority proof, not R5 evidence, and "
            "cannot unlock R6, lobe authority, externality, comparative claims, or commercial activation."
        ),
        "summary": {
            "case_count": len(case_rows),
            "route_advantage_case_count": route_advantage_case_count,
            "router_advantage_visible": route_advantage_case_count > 0,
            "staged_recombination_case_count": staged_recombination_case_count,
            "drop_or_rework_case_count": drop_or_rework_case_count,
        },
        "entrants": [
            {
                "adapter_id": entrant["adapter_id"],
                "adapter_version": entrant["adapter_version"],
                "job_dir": entrant["job_dir"],
                "job_id": entrant["job_id"],
            }
            for entrant in entrants
        ],
        "case_rows": case_rows,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a lab-only staged router-shadow opportunity check on tied verified-entrant cases."
    )
    parser.add_argument("--suite", default=DEFAULT_SUITE_REL)
    parser.add_argument("--job-dir", action="append", required=True, help="Verified factory job_dir. Repeat for multiple entrants.")
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    suite = _load_json_dict(_resolve(root, str(args.suite)), name="verified_tie_router_shadow_suite")
    job_dirs = [_resolve(root, str(item)) for item in args.job_dir]

    report = build_verified_tie_router_shadow_report(
        root=root,
        suite=suite,
        job_dirs=job_dirs,
        suite_ref=str(args.suite),
    )
    output_path = _resolve(root, str(args.output))
    write_json_stable(output_path, report)
    print(json.dumps(report["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
