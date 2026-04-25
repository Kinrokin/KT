from __future__ import annotations

import argparse
import json
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
    rows = suite.get("cases")
    if not isinstance(rows, list):
        raise RuntimeError("FAIL_CLOSED: scorecard suite cases missing")
    result: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        case_id = str(row.get("case_id", "")).strip()
        if case_id:
            result[case_id] = row
    return result


def _is_generalist(adapter_id: str) -> bool:
    return "generalist" in str(adapter_id).strip().lower()


def build_router_lab_specialist_gap_packet(
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

    if str(scorecard.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: scorecard mode must remain lab-only")
    if str(tie_report.get("mode", "")).strip() != "LAB_ONLY_NONCANONICAL":
        raise RuntimeError("FAIL_CLOSED: tie report mode must remain lab-only")

    scorecard_summary = scorecard.get("summary")
    scorecard_rows = scorecard.get("case_rows")
    tie_rows = tie_report.get("case_rows")
    if not isinstance(scorecard_summary, dict) or not isinstance(scorecard_rows, list) or not isinstance(tie_rows, list):
        raise RuntimeError("FAIL_CLOSED: scorecard or tie report incomplete")

    case_defs = _case_map_from_suite(scorecard_suite)
    wins_by_adapter = scorecard_summary.get("wins_by_adapter")
    if not isinstance(wins_by_adapter, dict):
        raise RuntimeError("FAIL_CLOSED: wins_by_adapter missing")

    zero_win_entrants = sorted(
        adapter_id
        for adapter_id, raw_wins in wins_by_adapter.items()
        if int(raw_wins) == 0
    )

    generalist_owned_cases: List[Dict[str, Any]] = []
    tie_cases: List[Dict[str, Any]] = []
    for row in scorecard_rows:
        if not isinstance(row, dict):
            continue
        case_id = str(row.get("case_id", "")).strip()
        winner_ids = [str(item).strip() for item in row.get("winner_adapter_ids", []) if str(item).strip()]
        case_def = case_defs.get(case_id, {})
        if bool(row.get("tie")):
            tie_cases.append(
                {
                    "case_id": case_id,
                    "winner_adapter_ids": winner_ids,
                    "task_text": str(case_def.get("task_text", "")).strip(),
                }
            )
        if len(winner_ids) == 1 and _is_generalist(winner_ids[0]):
            generalist_owned_cases.append(
                {
                    "case_id": case_id,
                    "current_owner_adapter_id": winner_ids[0],
                    "task_text": str(case_def.get("task_text", "")).strip(),
                    "required_terms": list(case_def.get("required_terms", [])),
                    "preferred_genotype": case_def.get("preferred_genotype", {}),
                }
            )

    route_pair_counts: Dict[str, int] = {}
    for row in tie_rows:
        if not isinstance(row, dict) or not bool(row.get("route_advantage")):
            continue
        adapter_ids = [str(item).strip() for item in row.get("routed_adapter_ids", []) if str(item).strip()]
        if not adapter_ids:
            continue
        pair_key = " -> ".join(adapter_ids)
        route_pair_counts[pair_key] = route_pair_counts.get(pair_key, 0) + 1

    dominant_route_pairs = [
        {"route_pair": pair, "case_count": count}
        for pair, count in sorted(route_pair_counts.items(), key=lambda item: (-item[1], item[0]))
    ]

    targeted_specialist_candidates = [
        {
            "case_id": row["case_id"],
            "target_reason": "GENERALIST_OWNS_CASE",
            "candidate_terms": row["required_terms"],
            "candidate_genotype": row["preferred_genotype"],
        }
        for row in generalist_owned_cases
    ]

    posture = (
        "SPECIALIST_BROADENING_RECOMMENDED"
        if generalist_owned_cases or zero_win_entrants
        else "SPECIALIST_COVERAGE_BALANCED"
    )

    return {
        "schema_id": "kt.router_lab_specialist_gap_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "claim_boundary": (
            "This packet is lab-only and noncanonical. It identifies specialist-coverage gaps in the verified-entrant "
            "router-shadow cohort, but it is not tournament truth, not R5 evidence, does not earn router superiority, "
            "and cannot unlock R6, lobe authority, externality, comparative claims, or commercial activation."
        ),
        "scorecard_suite_ref": scorecard_suite_ref,
        "tie_suite_ref": tie_suite_ref,
        "job_dirs": [path.as_posix() for path in canonical_job_dirs],
        "summary": {
            "entrant_count": int(scorecard_summary.get("entrant_count", 0)),
            "case_count": int(scorecard_summary.get("case_count", 0)),
            "generalist_owned_case_count": len(generalist_owned_cases),
            "zero_win_entrant_count": len(zero_win_entrants),
            "tie_case_count": len(tie_cases),
            "dominant_route_pair_count": len(dominant_route_pairs),
        },
        "specialist_gap_posture": posture,
        "generalist_owned_cases": generalist_owned_cases,
        "zero_win_entrants": zero_win_entrants,
        "tied_scorecard_cases": tie_cases,
        "dominant_route_pairs": dominant_route_pairs,
        "targeted_specialist_candidates": targeted_specialist_candidates,
        "recommendation": (
            "BROADEN_SPECIALISTS_ON_GENERALIST_OWNED_CASES_AND_REEVALUATE_ZERO_WIN_ENTRANTS"
            if posture == "SPECIALIST_BROADENING_RECOMMENDED"
            else "KEEP_CURRENT_SPECIALIST_COHORT_AND_CONTINUE_LAB_LOOP"
        ),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a lab-only specialist-gap packet over verified-entrant router-shadow evidence."
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

    packet = build_router_lab_specialist_gap_packet(
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
