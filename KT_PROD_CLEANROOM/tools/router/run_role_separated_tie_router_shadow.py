from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.router.run_verified_entrant_lab_scorecard import (
    _load_json_dict,
    _load_policy_bundles,
    _ordered_unique,
    _resolve,
    _score_bundle_for_case,
)


DEFAULT_SUITE_REL = "KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/ROUTER_LAB/ROLE_SEPARATED_TIE_ROUTER_SHADOW_SUITE_V1.json"


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


def _coerce_id_list(raw: Any) -> List[str]:
    if not isinstance(raw, list):
        return []
    return _ordered_unique(str(item).strip() for item in raw)


def _filter_stage_entrants(
    *,
    entrants: Sequence[Dict[str, Any]],
    stage: Dict[str, Any],
    prior_stage_rows: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    allowed_adapter_ids = set(_coerce_id_list(stage.get("allowed_adapter_ids")))
    disallowed_adapter_ids = set(_coerce_id_list(stage.get("disallowed_adapter_ids")))
    prior_adapter_ids = [str(row["adapter_id"]).strip() for row in prior_stage_rows]
    require_distinct_from_previous_stage = bool(stage.get("require_distinct_from_previous_stage", False))
    require_distinct_from_all_prior_stages = bool(stage.get("require_distinct_from_all_prior_stages", False))

    filtered: List[Dict[str, Any]] = []
    for entrant in entrants:
        adapter_id = str(entrant["adapter_id"]).strip()
        if allowed_adapter_ids and adapter_id not in allowed_adapter_ids:
            continue
        if adapter_id in disallowed_adapter_ids:
            continue
        if require_distinct_from_previous_stage and prior_adapter_ids and adapter_id == prior_adapter_ids[-1]:
            continue
        if require_distinct_from_all_prior_stages and adapter_id in prior_adapter_ids:
            continue
        filtered.append(entrant)
    return filtered


def _best_stage_pick(
    *,
    entrants: Sequence[Dict[str, Any]],
    case_id: str,
    stage: Dict[str, Any],
    prior_stage_rows: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    filtered_entrants = _filter_stage_entrants(entrants=entrants, stage=stage, prior_stage_rows=prior_stage_rows)
    stage_id = str(stage.get("stage_id", "")).strip() or "UNKNOWN_STAGE"
    if not filtered_entrants:
        raise RuntimeError(f"FAIL_CLOSED: {case_id}/{stage_id} had no entrants satisfying role constraints")

    best_row: Optional[Dict[str, Any]] = None
    for entrant in filtered_entrants:
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
            "stage_id": stage_id,
            "stage_role_constraints": {
                "allowed_adapter_ids": _coerce_id_list(stage.get("allowed_adapter_ids")),
                "disallowed_adapter_ids": _coerce_id_list(stage.get("disallowed_adapter_ids")),
                "require_distinct_from_previous_stage": bool(stage.get("require_distinct_from_previous_stage", False)),
                "require_distinct_from_all_prior_stages": bool(stage.get("require_distinct_from_all_prior_stages", False)),
            },
        }
        if best_row is None or (float(row["score"]), row["bundle_id"]) > (float(best_row["score"]), best_row["bundle_id"]):
            best_row = row
    if best_row is None:
        raise RuntimeError(f"FAIL_CLOSED: {case_id}/{stage_id} had no valid stage pick")
    return best_row


def build_role_separated_tie_router_shadow_report(
    *,
    root: Path,
    suite: Dict[str, Any],
    job_dirs: Sequence[Path],
    suite_ref: str = DEFAULT_SUITE_REL,
) -> Dict[str, Any]:
    cases = suite.get("cases")
    if not isinstance(cases, list) or not cases:
        raise RuntimeError("FAIL_CLOSED: role-separated tie router shadow suite cases missing")

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
    role_separated_case_count = 0
    family_case_counts: Counter[str] = Counter()
    family_route_advantage_counts: Counter[str] = Counter()
    family_role_separated_counts: Counter[str] = Counter()

    for case in cases:
        if not isinstance(case, dict):
            continue
        case_id = str(case.get("case_id", "")).strip()
        if not case_id:
            raise RuntimeError("FAIL_CLOSED: role-separated tie router case missing case_id")
        pattern_family = str(case.get("pattern_family", "")).strip() or case_id
        baseline_case = case.get("single_case_baseline")
        if not isinstance(baseline_case, dict):
            raise RuntimeError(f"FAIL_CLOSED: {case_id} missing single_case_baseline")
        stages = case.get("stages")
        if not isinstance(stages, list) or not stages:
            raise RuntimeError(f"FAIL_CLOSED: {case_id} missing stages")

        best_single = _best_single_case(entrants=entrants, case=baseline_case)
        stage_rows: List[Dict[str, Any]] = []
        for raw_stage in stages:
            if not isinstance(raw_stage, dict):
                continue
            stage_rows.append(
                _best_stage_pick(
                    entrants=entrants,
                    case_id=case_id,
                    stage=raw_stage,
                    prior_stage_rows=stage_rows,
                )
            )
        if not stage_rows:
            raise RuntimeError(f"FAIL_CLOSED: {case_id} had no valid stages")

        routed_score = round(sum(float(row["score"]) for row in stage_rows), 6)
        best_single_score = round(float(best_single["score"]), 6)
        routed_adapter_ids = [str(row["adapter_id"]) for row in stage_rows]
        multi_adapter_route = len(set(routed_adapter_ids)) > 1
        route_advantage = routed_score > best_single_score and multi_adapter_route
        role_separation_enforced = any(
            row["stage_role_constraints"]["allowed_adapter_ids"]
            or row["stage_role_constraints"]["disallowed_adapter_ids"]
            or row["stage_role_constraints"]["require_distinct_from_previous_stage"]
            or row["stage_role_constraints"]["require_distinct_from_all_prior_stages"]
            for row in stage_rows
        )

        if route_advantage:
            route_advantage_case_count += 1
            family_route_advantage_counts[pattern_family] += 1
        if route_advantage and role_separation_enforced:
            role_separated_case_count += 1
            family_role_separated_counts[pattern_family] += 1

        family_case_counts[pattern_family] += 1

        case_rows.append(
            {
                "case_id": case_id,
                "pattern_family": pattern_family,
                "notes": str(case.get("notes", "")).strip(),
                "best_single_baseline": best_single,
                "routed_stage_picks": stage_rows,
                "routed_adapter_ids": routed_adapter_ids,
                "routed_score": routed_score,
                "best_single_score": best_single_score,
                "multi_adapter_route": multi_adapter_route,
                "route_advantage": route_advantage,
                "role_separation_enforced": role_separation_enforced,
                "route_advantage_delta": round(routed_score - best_single_score, 6),
                "recommended_action": "KEEP_AND_EXPAND" if route_advantage else "HOLD_OR_REWORK",
            }
        )

    return {
        "schema_id": "kt.role_separated_tie_router_shadow_report.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "suite_ref": str(suite_ref),
        "claim_boundary": (
            "This report is lab-only. It measures forced role-separated staged router-shadow opportunity "
            "over the live verified entrant cohort, but it is not tournament truth, not router superiority "
            "proof, not R5 evidence, and cannot unlock R6, lobe authority, externality, comparative claims, "
            "or commercial activation."
        ),
        "summary": {
            "case_count": len(case_rows),
            "route_advantage_case_count": route_advantage_case_count,
            "role_separated_case_count": role_separated_case_count,
            "router_advantage_visible": route_advantage_case_count > 0,
            "family_case_counts": dict(sorted(family_case_counts.items())),
            "family_route_advantage_counts": dict(sorted(family_route_advantage_counts.items())),
            "family_role_separated_counts": dict(sorted(family_role_separated_counts.items())),
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
        description="Run a lab-only forced role-separated router-shadow check on verified entrants."
    )
    parser.add_argument("--suite", default=DEFAULT_SUITE_REL)
    parser.add_argument("--job-dir", action="append", required=True, help="Verified factory job_dir. Repeat for multiple entrants.")
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    suite = _load_json_dict(_resolve(root, str(args.suite)), name="role_separated_tie_router_shadow_suite")
    job_dirs = [_resolve(root, str(item)) for item in args.job_dir]

    report = build_role_separated_tie_router_shadow_report(
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
