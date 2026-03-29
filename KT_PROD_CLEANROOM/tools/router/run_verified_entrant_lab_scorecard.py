from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.training.fl3_factory.eval import _apply_policy_bundle


DEFAULT_SUITE_REL = "KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/ROUTER_LAB/VERIFIED_ENTRANT_LAB_SCORECARD_SUITE_V1.json"


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _load_json_dict(path: Path, *, name: str) -> Dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"FAIL_CLOSED: expected JSON object for {name}: {path.as_posix()}")
    return payload


def _ordered_unique(items: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    ordered: List[str] = []
    for item in items:
        value = str(item).strip()
        if not value or value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def _load_policy_bundles(*, root: Path, job_dir: Path) -> List[Dict[str, Any]]:
    train_manifest = _load_json_dict(job_dir / "train_manifest.json", name="train_manifest")
    bundle = train_manifest.get("output_bundle")
    if not isinstance(bundle, dict):
        raise RuntimeError(f"FAIL_CLOSED: missing output_bundle in {job_dir.as_posix()}/train_manifest.json")

    raw_path = str(bundle.get("artifact_path", "")).strip()
    if not raw_path:
        raise RuntimeError(f"FAIL_CLOSED: output_bundle.artifact_path missing in {job_dir.as_posix()}/train_manifest.json")

    bundle_path = _resolve(root, raw_path)
    if not bundle_path.exists():
        raise RuntimeError(f"FAIL_CLOSED: policy bundle artifact missing: {bundle_path.as_posix()}")

    bundles: List[Dict[str, Any]] = []
    for line in bundle_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise RuntimeError(f"FAIL_CLOSED: invalid policy bundle row in {bundle_path.as_posix()}")
        bundles.append(row)
    if not bundles:
        raise RuntimeError(f"FAIL_CLOSED: no policy bundles found in {bundle_path.as_posix()}")
    return bundles


def _score_bundle_for_case(*, bundle: Dict[str, Any], case: Dict[str, Any]) -> Dict[str, Any]:
    genotype = bundle.get("genotype") if isinstance(bundle.get("genotype"), dict) else {}
    preferred = case.get("preferred_genotype") if isinstance(case.get("preferred_genotype"), dict) else {}
    weights = case.get("weights") if isinstance(case.get("weights"), dict) else {}
    discouraged = case.get("discouraged_genotype") if isinstance(case.get("discouraged_genotype"), dict) else {}
    required_terms = [str(term).strip().lower() for term in case.get("required_terms", []) if str(term).strip()]
    task_text = str(case.get("task_text", "")).strip()
    refusal_penalty = float(case.get("refusal_penalty", 1.5))
    required_term_weight = float(case.get("required_term_weight", 0.5))

    output = _apply_policy_bundle(prompt=task_text, bundle=bundle)
    field_matches: List[Dict[str, Any]] = []
    score = 0.0

    for field, desired in preferred.items():
        weight = float(weights.get(field, 1.0))
        actual = str(genotype.get(field, "")).strip()
        matched = actual == str(desired).strip()
        if matched:
            score += weight
        field_matches.append(
            {
                "field": str(field),
                "expected": str(desired),
                "actual": actual,
                "matched": matched,
                "weight": weight,
            }
        )

    penalty_rows: List[Dict[str, Any]] = []
    for field, discouraged_value in discouraged.items():
        penalty_weight = float(weights.get(f"discouraged::{field}", 1.0))
        actual = str(genotype.get(field, "")).strip()
        triggered = actual == str(discouraged_value).strip()
        if triggered:
            score -= penalty_weight
        penalty_rows.append(
            {
                "field": str(field),
                "discouraged": str(discouraged_value),
                "actual": actual,
                "triggered": triggered,
                "weight": penalty_weight,
            }
        )

    lowered_output = output.lower()
    covered_terms = [term for term in required_terms if term in lowered_output]
    score += float(len(covered_terms)) * required_term_weight

    refused = output.startswith("REFUSE|")
    if refused:
        score -= refusal_penalty

    return {
        "bundle_id": str(bundle.get("bundle_id", "")).strip(),
        "covered_terms": covered_terms,
        "field_matches": field_matches,
        "genotype": genotype,
        "output_preview": output[:160],
        "penalties": penalty_rows,
        "refused": refused,
        "score": round(score, 6),
    }


def build_verified_entrant_lab_scorecard(
    *,
    root: Path,
    suite: Dict[str, Any],
    job_dirs: Sequence[Path],
    suite_ref: str = DEFAULT_SUITE_REL,
) -> Dict[str, Any]:
    cases = suite.get("cases")
    if not isinstance(cases, list) or not cases:
        raise RuntimeError("FAIL_CLOSED: lab scorecard suite cases missing")

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
    wins_by_adapter: Dict[str, int] = {entrant["adapter_id"]: 0 for entrant in entrants}
    tie_case_count = 0

    for case in cases:
        if not isinstance(case, dict):
            continue
        case_id = str(case.get("case_id", "")).strip()
        if not case_id:
            raise RuntimeError("FAIL_CLOSED: scorecard case missing case_id")

        entrant_scores: List[Dict[str, Any]] = []
        best_score = None
        winner_ids: List[str] = []
        for entrant in entrants:
            best_bundle = max(
                (_score_bundle_for_case(bundle=bundle, case=case) for bundle in entrant["bundles"]),
                key=lambda row: (float(row["score"]), str(row["bundle_id"])),
            )
            entrant_row = {
                "adapter_id": entrant["adapter_id"],
                "adapter_version": entrant["adapter_version"],
                "best_bundle_id": best_bundle["bundle_id"],
                "best_bundle_genotype": best_bundle["genotype"],
                "covered_terms": best_bundle["covered_terms"],
                "field_matches": best_bundle["field_matches"],
                "job_dir": entrant["job_dir"],
                "output_preview": best_bundle["output_preview"],
                "penalties": best_bundle["penalties"],
                "refused": best_bundle["refused"],
                "score": best_bundle["score"],
            }
            entrant_scores.append(entrant_row)
            score = float(best_bundle["score"])
            if best_score is None or score > best_score:
                best_score = score
                winner_ids = [entrant["adapter_id"]]
            elif score == best_score:
                winner_ids.append(entrant["adapter_id"])

        winner_ids = _ordered_unique(winner_ids)
        tie = len(winner_ids) > 1
        if tie:
            tie_case_count += 1
        else:
            wins_by_adapter[winner_ids[0]] += 1

        entrant_scores.sort(key=lambda row: (-float(row["score"]), row["adapter_id"]))
        case_rows.append(
            {
                "case_id": case_id,
                "notes": str(case.get("notes", "")).strip(),
                "task_text": str(case.get("task_text", "")).strip(),
                "tie": tie,
                "winner_adapter_ids": winner_ids,
                "winning_score": round(float(best_score or 0.0), 6),
                "entrant_scores": entrant_scores,
            }
        )

    differentiated_case_count = len(case_rows) - tie_case_count
    return {
        "schema_id": "kt.verified_entrant_lab_scorecard.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "suite_ref": str(suite_ref),
        "claim_boundary": (
            "This scorecard is lab-only. It scores verified entrant policy bundles against a richer "
            "mixed-task suite, but it does not count as tournament promotion, router superiority, R5 proof, "
            "R6 authorization, lobe authority, externality, comparative claims, or commercial readiness."
        ),
        "summary": {
            "case_count": len(case_rows),
            "entrant_count": len(entrants),
            "differentiated_case_count": differentiated_case_count,
            "tie_case_count": tie_case_count,
            "wins_by_adapter": wins_by_adapter,
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
        description="Run a noncanonical lab-only scorecard over verified entrant policy bundles."
    )
    parser.add_argument("--suite", default=DEFAULT_SUITE_REL)
    parser.add_argument("--job-dir", action="append", required=True, help="Verified factory job_dir. Repeat for multiple entrants.")
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    suite = _load_json_dict(_resolve(root, str(args.suite)), name="verified_entrant_lab_suite")
    job_dirs = [_resolve(root, str(item)) for item in args.job_dir]

    report = build_verified_entrant_lab_scorecard(
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
