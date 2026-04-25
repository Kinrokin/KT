from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.router.run_verified_entrant_lab_scorecard import (
    DEFAULT_SUITE_REL as SCORECARD_SUITE_REL,
    _load_json_dict,
    _load_policy_bundles,
    _resolve,
    _score_bundle_for_case,
    build_verified_entrant_lab_scorecard,
)
from tools.router.run_verified_tie_router_shadow import (
    DEFAULT_SUITE_REL as TIE_SUITE_REL,
    build_verified_tie_router_shadow_report,
)


DIRECT_REHAB_GAP_THRESHOLD = 1.0


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


def _case_map_from_suite(suite: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    cases = suite.get("cases")
    if not isinstance(cases, list):
        raise RuntimeError("FAIL_CLOSED: scorecard suite cases missing")
    result: Dict[str, Dict[str, Any]] = {}
    for row in cases:
        if not isinstance(row, dict):
            continue
        case_id = str(row.get("case_id", "")).strip()
        if case_id:
            result[case_id] = row
    return result


def _load_entrants_with_bundles(*, root: Path, job_dirs: Sequence[Path]) -> List[Dict[str, Any]]:
    entrants: List[Dict[str, Any]] = []
    for job_dir in job_dirs:
        resolved = job_dir.resolve()
        job = _load_json_dict(resolved / "job.json", name="job")
        bundles = _load_policy_bundles(root=root, job_dir=resolved)
        entrants.append(
            {
                "adapter_id": str(job.get("adapter_id", "")).strip(),
                "adapter_version": str(job.get("adapter_version", "")).strip(),
                "job_dir": resolved.as_posix(),
                "bundles": bundles,
            }
        )
    return entrants


def _best_case_score_for_entrant(*, entrant: Dict[str, Any], case: Dict[str, Any]) -> Dict[str, Any]:
    best = max(
        (_score_bundle_for_case(bundle=bundle, case=case) for bundle in entrant["bundles"]),
        key=lambda row: (float(row["score"]), str(row["bundle_id"])),
    )
    return {
        "adapter_id": entrant["adapter_id"],
        "adapter_version": entrant["adapter_version"],
        "job_dir": entrant["job_dir"],
        "bundle_id": str(best["bundle_id"]),
        "genotype": best["genotype"],
        "score": float(best["score"]),
        "covered_terms": list(best["covered_terms"]),
    }


def build_router_lab_specialist_rehabilitation_packet(
    *,
    root: Path,
    scorecard_suite: Dict[str, Any],
    tie_suite: Dict[str, Any],
    scorecard_suite_ref: str,
    tie_suite_ref: str,
    job_dirs: Sequence[Path],
) -> Dict[str, Any]:
    canonical_job_dirs = _ordered_unique_paths(job_dirs)
    if not canonical_job_dirs:
        raise RuntimeError("FAIL_CLOSED: no job dirs supplied")

    scorecard = build_verified_entrant_lab_scorecard(
        root=root,
        suite=scorecard_suite,
        suite_ref=scorecard_suite_ref,
        job_dirs=canonical_job_dirs,
    )
    tie_report = build_verified_tie_router_shadow_report(
        root=root,
        suite=tie_suite,
        suite_ref=tie_suite_ref,
        job_dirs=canonical_job_dirs,
    )

    scorecard_rows = scorecard.get("case_rows")
    scorecard_summary = scorecard.get("summary")
    tie_rows = tie_report.get("case_rows")
    if not isinstance(scorecard_rows, list) or not isinstance(scorecard_summary, dict) or not isinstance(tie_rows, list):
        raise RuntimeError("FAIL_CLOSED: missing scorecard or tie-router structures")

    entrants = _load_entrants_with_bundles(root=root, job_dirs=canonical_job_dirs)
    entrants_by_id = {entrant["adapter_id"]: entrant for entrant in entrants}
    wins_by_adapter = scorecard_summary.get("wins_by_adapter")
    if not isinstance(wins_by_adapter, dict):
        raise RuntimeError("FAIL_CLOSED: wins_by_adapter missing")

    zero_win_entrants = sorted(
        adapter_id
        for adapter_id, raw_wins in wins_by_adapter.items()
        if int(raw_wins) == 0
    )
    route_pair_participation: Dict[str, int] = {adapter_id: 0 for adapter_id in entrants_by_id}
    for row in tie_rows:
        if not isinstance(row, dict) or not bool(row.get("route_advantage", False)):
            continue
        for adapter_id in row.get("routed_adapter_ids", []):
            key = str(adapter_id).strip()
            if key:
                route_pair_participation[key] = route_pair_participation.get(key, 0) + 1

    case_defs = _case_map_from_suite(scorecard_suite)
    generalist_owned_rows: List[Dict[str, Any]] = []
    for row in scorecard_rows:
        if not isinstance(row, dict):
            continue
        winner_ids = [str(item).strip() for item in row.get("winner_adapter_ids", []) if str(item).strip()]
        if len(winner_ids) != 1:
            continue
        owner = winner_ids[0]
        if "generalist" not in owner.lower():
            continue
        case_id = str(row.get("case_id", "")).strip()
        case_def = case_defs.get(case_id, {})
        candidate_rows: List[Dict[str, Any]] = []
        owner_score = float(row.get("winning_score", 0.0))
        for adapter_id in zero_win_entrants:
            entrant = entrants_by_id.get(adapter_id)
            if entrant is None:
                continue
            scored = _best_case_score_for_entrant(entrant=entrant, case=case_def)
            score_gap = round(owner_score - float(scored["score"]), 6)
            candidate_rows.append(
                {
                    "adapter_id": adapter_id,
                    "best_bundle_id": scored["bundle_id"],
                    "best_bundle_genotype": scored["genotype"],
                    "best_score": round(float(scored["score"]), 6),
                    "score_gap_to_current_owner": score_gap,
                    "route_pair_participation_count": route_pair_participation.get(adapter_id, 0),
                    "covered_terms": scored["covered_terms"],
                }
            )
        candidate_rows.sort(
            key=lambda item: (
                float(item["score_gap_to_current_owner"]),
                -int(item["route_pair_participation_count"]),
                item["adapter_id"],
            )
        )
        generalist_owned_rows.append(
            {
                "case_id": case_id,
                "current_owner_adapter_id": owner,
                "current_owner_score": owner_score,
                "task_text": str(case_def.get("task_text", "")).strip(),
                "required_terms": list(case_def.get("required_terms", [])),
                "preferred_genotype": case_def.get("preferred_genotype", {}),
                "candidate_zero_win_rehabilitations": candidate_rows,
            }
        )

    entrant_recommendations: List[Dict[str, Any]] = []
    for adapter_id in zero_win_entrants:
        best_case: Optional[Dict[str, Any]] = None
        for row in generalist_owned_rows:
            for candidate in row["candidate_zero_win_rehabilitations"]:
                if candidate["adapter_id"] != adapter_id:
                    continue
                candidate_case = {
                    "case_id": row["case_id"],
                    "score_gap_to_current_owner": candidate["score_gap_to_current_owner"],
                    "route_pair_participation_count": candidate["route_pair_participation_count"],
                }
                if best_case is None or (
                    float(candidate_case["score_gap_to_current_owner"]),
                    -int(candidate_case["route_pair_participation_count"]),
                    candidate_case["case_id"],
                ) < (
                    float(best_case["score_gap_to_current_owner"]),
                    -int(best_case["route_pair_participation_count"]),
                    best_case["case_id"],
                ):
                    best_case = candidate_case

        route_useful = int(route_pair_participation.get(adapter_id, 0)) > 0
        direct_gap = float(best_case["score_gap_to_current_owner"]) if best_case is not None else None
        if route_useful:
            disposition = "REHABILITATE_AS_ROUTE_SPECIALIST"
        elif direct_gap is not None and direct_gap <= DIRECT_REHAB_GAP_THRESHOLD:
            disposition = "REHABILITATE_AS_DIRECT_CASE_CHALLENGER"
        else:
            disposition = "RETIRE_OR_REWORK"

        entrant_recommendations.append(
            {
                "adapter_id": adapter_id,
                "route_pair_participation_count": int(route_pair_participation.get(adapter_id, 0)),
                "best_target_case": best_case,
                "disposition": disposition,
            }
        )

    entrant_recommendations.sort(key=lambda row: (row["disposition"], row["adapter_id"]))

    return {
        "schema_id": "kt.router_lab_specialist_rehabilitation_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "claim_boundary": (
            "This packet is lab-only and noncanonical. It recommends targeted rehabilitation or retirement of zero-win entrants "
            "against current generalist-owned cases, but it is not tournament truth, not R5 evidence, does not earn router superiority, "
            "and cannot unlock R6, lobe authority, externality, comparative claims, or commercial activation."
        ),
        "scorecard_suite_ref": scorecard_suite_ref,
        "tie_suite_ref": tie_suite_ref,
        "job_dirs": [path.as_posix() for path in canonical_job_dirs],
        "summary": {
            "entrant_count": int(scorecard_summary.get("entrant_count", 0)),
            "zero_win_entrant_count": len(zero_win_entrants),
            "generalist_owned_case_count": len(generalist_owned_rows),
        },
        "generalist_owned_case_targets": generalist_owned_rows,
        "zero_win_entrant_recommendations": entrant_recommendations,
        "recommendation": "RUN_TARGETED_SPECIALIST_REHAB_ON_GENERALIST_OWNED_CASES_AND_REEVALUATE",
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a lab-only specialist rehabilitation packet from current verified-entrant router-shadow evidence."
    )
    parser.add_argument("--scorecard-suite", default=SCORECARD_SUITE_REL)
    parser.add_argument("--tie-suite", default=TIE_SUITE_REL)
    parser.add_argument("--job-dir", action="append", required=True)
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

    packet = build_router_lab_specialist_rehabilitation_packet(
        root=root,
        scorecard_suite=scorecard_suite,
        tie_suite=tie_suite,
        scorecard_suite_ref=scorecard_suite_ref,
        tie_suite_ref=tie_suite_ref,
        job_dirs=job_dirs,
    )
    output_path = _resolve(root, str(args.output))
    write_json_stable(output_path, packet)
    print(json.dumps(packet["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
