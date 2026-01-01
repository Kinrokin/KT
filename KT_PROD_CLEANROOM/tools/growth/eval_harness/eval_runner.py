from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from benchmark_suite import load_suite
from delta_ledger import append_delta
from eval_schemas import (
    ALLOWED_METRICS,
    BenchmarkResultSchema,
    BenchmarkRunSchema,
    EvalSchemaError,
    LearningDeltaSchema,
)
from report_builder import write_report


def _require_json_object(path: Path) -> Dict[str, object]:
    raw = path.read_text(encoding="utf-8")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise EvalSchemaError(f"{path.as_posix()} must be JSON object (fail-closed)")
    return obj


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except Exception:
        return False


def _resolve_artifact_ref(*, artifacts_root: Path, ref: str) -> Path:
    root = artifacts_root.resolve()
    p = Path(ref)
    resolved = p.resolve(strict=True) if p.is_absolute() else (root / p).resolve(strict=True)
    if not _is_relative_to(resolved, root):
        raise EvalSchemaError(f"input_ref escapes artifacts_root: {ref} (fail-closed)")
    return resolved


def _normalize_run_base(ref_path: Path) -> Path:
    if ref_path.is_dir():
        return ref_path
    if ref_path.name in {"runner_record.json", "run_record.json"}:
        return ref_path
    raise EvalSchemaError("Run references must be a run directory, runner_record.json, or run_record.json (fail-closed)")


def _c019_run_dir_from_run_id(*, artifacts_root: Path, kernel_target: str, run_id: str) -> Path:
    if not isinstance(run_id, str) or len(run_id) != 64:
        raise EvalSchemaError("run_id invalid (fail-closed)")
    try:
        int(run_id, 16)
    except Exception:
        raise EvalSchemaError("run_id must be hex (fail-closed)")

    candidate = (artifacts_root / "c019_runs" / kernel_target / run_id).resolve(strict=True)
    if not _is_relative_to(candidate, artifacts_root):
        raise EvalSchemaError("Derived c019 run dir escapes artifacts_root (fail-closed)")
    return candidate


def _load_c019_bundle(*, artifacts_root: Path, kernel_target: str, ref_path: Path) -> Dict[str, object]:
    # Accepted inputs (both must remain under artifacts_root):
    # - a C019 run directory (contains runner_record/governance_report/replay_report)
    # - a C019 runner_record.json
    # - a C018 epoch run_record.json (contains run_id; used to locate the C019 run directory)
    if ref_path.is_dir():
        run_base = ref_path
    elif ref_path.name == "runner_record.json":
        run_base = ref_path.parent
    elif ref_path.name == "run_record.json":
        epoch_run = _require_json_object(ref_path)
        run_id = epoch_run.get("run_id")
        if not isinstance(run_id, str):
            raise EvalSchemaError(f"{ref_path.as_posix()} missing run_id (fail-closed)")
        run_base = _c019_run_dir_from_run_id(artifacts_root=artifacts_root, kernel_target=kernel_target, run_id=run_id)
        # Cross-check outcome when available (fail-closed on divergence).
        if "outcome" in epoch_run and epoch_run.get("outcome") not in {"PASS", "FAIL", "REFUSE", "INFEASIBLE"}:
            raise EvalSchemaError(f"{ref_path.as_posix()} invalid outcome (fail-closed)")
    else:
        raise EvalSchemaError("Unsupported run reference (fail-closed)")

    runner_record_path = run_base / "runner_record.json"
    governance_report_path = run_base / "governance_report.json"
    replay_report_path = run_base / "replay_report.json"

    runner = _require_json_object(runner_record_path)
    for key in ("crucible_id", "outcome", "kernel_target", "run_id", "replay_pass", "governance_pass"):
        if key not in runner:
            raise EvalSchemaError(f"{runner_record_path.as_posix()} missing {key} (fail-closed)")

    governance = _require_json_object(governance_report_path)
    if "types" not in governance or "count" not in governance:
        raise EvalSchemaError(f"{governance_report_path.as_posix()} missing types/count (fail-closed)")
    if not isinstance(governance.get("types"), list) or not all(isinstance(x, str) for x in governance.get("types", [])):
        raise EvalSchemaError(f"{governance_report_path.as_posix()} types invalid (fail-closed)")
    if not isinstance(governance.get("count"), int):
        raise EvalSchemaError(f"{governance_report_path.as_posix()} count invalid (fail-closed)")

    replay = _require_json_object(replay_report_path)
    if replay.get("status") != "PASS":
        raise EvalSchemaError(f"{replay_report_path.as_posix()} status != PASS (fail-closed)")

    return {
        "runner_record": runner,
        "governance_report": governance,
        "replay_report": replay,
        "run_base": run_base.as_posix(),
    }


def _c019_run_dir_for_allowlist(*, artifacts_root: Path, kernel_target: str, ref_path: Path) -> Path:
    if ref_path.is_dir():
        return ref_path
    if ref_path.name == "runner_record.json":
        return ref_path.parent
    if ref_path.name == "run_record.json":
        epoch_run = _require_json_object(ref_path)
        run_id = epoch_run.get("run_id")
        if not isinstance(run_id, str):
            raise EvalSchemaError(f"{ref_path.as_posix()} missing run_id (fail-closed)")
        return _c019_run_dir_from_run_id(artifacts_root=artifacts_root, kernel_target=kernel_target, run_id=run_id)
    raise EvalSchemaError("Unsupported run reference in allowlist (fail-closed)")


def _metric_values_from_records(bundles: Sequence[Dict[str, object]]) -> Dict[str, float]:
    total = len(bundles)
    if total == 0:
        raise EvalSchemaError("No run records supplied (fail-closed)")
    pass_count = sum(1 for b in bundles if b.get("runner_record", {}).get("outcome") == "PASS")
    pass_rate = pass_count / total
    return {
        "pass_rate": pass_rate,
        "fail_rate": 1.0 - pass_rate,
    }


def _case_score(expected: Dict[str, float], weights: Dict[str, float], observed: Dict[str, float]) -> float:
    if not expected:
        raise EvalSchemaError("expected_metrics must not be empty (fail-closed)")
    total_weight = 0.0
    total_score = 0.0
    for name, target in expected.items():
        if name not in ALLOWED_METRICS:
            raise EvalSchemaError(f"metric {name} not allowed (fail-closed)")
        obs = observed.get(name)
        if obs is None:
            raise EvalSchemaError(f"metric {name} missing (fail-closed)")
        weight = float(weights.get(name, 1.0))
        total_weight += weight
        score = max(0.0, 1.0 - abs(obs - float(target)))
        total_score += weight * score
    if total_weight <= 0:
        raise EvalSchemaError("metric_weights sum must be > 0 (fail-closed)")
    return total_score / total_weight


def run_eval(
    *,
    suite_path: Path,
    epoch_manifest_paths: Iterable[Path],
    run_record_paths: Iterable[Path],
    baseline_result_path: Optional[Path],
    artifacts_root: Path,
    ledger_path: Path,
) -> Dict[str, object]:
    suite = load_suite(suite_path)

    artifacts_root = artifacts_root.resolve(strict=True)
    if not artifacts_root.is_dir():
        raise EvalSchemaError("--artifacts-root must be a directory (fail-closed)")

    epoch_ids: List[str] = []
    for p in epoch_manifest_paths:
        manifest = _require_json_object(p)
        epoch_id = manifest.get("epoch_id")
        if not isinstance(epoch_id, str):
            raise EvalSchemaError(f"{p.as_posix()} missing epoch_id (fail-closed)")
        kernel_identity = manifest.get("kernel_identity")
        if not isinstance(kernel_identity, dict):
            raise EvalSchemaError(f"{p.as_posix()} missing kernel_identity (fail-closed)")
        if kernel_identity != suite.kernel_identity:
            raise EvalSchemaError(f"{p.as_posix()} kernel_identity != suite.kernel_identity (fail-closed)")
        epoch_ids.append(epoch_id)

    allowed_run_dirs: Set[str] = set()
    for p in run_record_paths:
        resolved = p.resolve(strict=True)
        if not _is_relative_to(resolved, artifacts_root):
            raise EvalSchemaError(f"--run-record escapes artifacts_root: {p.as_posix()} (fail-closed)")
        run_dir = _c019_run_dir_for_allowlist(
            artifacts_root=artifacts_root, kernel_target=str(suite.kernel_identity.get("kernel_target")), ref_path=_normalize_run_base(resolved)
        )
        allowed_run_dirs.add(run_dir.as_posix())

    per_case_scores: Dict[str, float] = {}
    for case in suite.cases:
        if len(case.input_refs) > int(case.bounds.get("max_inputs", 16)):
            raise EvalSchemaError(f"{case.case_id} exceeds bounds.max_inputs (fail-closed)")

        case_bundles: List[Dict[str, object]] = []
        for ref in case.input_refs:
            ref_path = _resolve_artifact_ref(artifacts_root=artifacts_root, ref=ref)
            normalized = _normalize_run_base(ref_path)
            run_dir = _c019_run_dir_for_allowlist(
                artifacts_root=artifacts_root, kernel_target=str(suite.kernel_identity.get("kernel_target")), ref_path=normalized
            ).as_posix()
            if run_dir not in allowed_run_dirs:
                raise EvalSchemaError(f"{case.case_id} references non-allowlisted run: {ref} (fail-closed)")
            bundle = _load_c019_bundle(artifacts_root=artifacts_root, kernel_target=str(suite.kernel_identity.get("kernel_target")), ref_path=normalized)
            runner = bundle["runner_record"]
            if runner.get("kernel_target") != suite.kernel_identity.get("kernel_target"):
                raise EvalSchemaError("kernel_target mismatch across run records (fail-closed)")
            case_bundles.append(bundle)

        observed = _metric_values_from_records(case_bundles)
        per_case_scores[case.case_id] = _case_score(case.expected_metrics, case.metric_weights, observed)

    aggregate_score = sum(per_case_scores.values()) / len(per_case_scores)

    run = BenchmarkRunSchema.build(suite_hash=suite.suite_hash, epoch_ids=epoch_ids, kernel_identity=suite.kernel_identity)
    regression_flag = False

    baseline_score: Optional[float] = None
    baseline_run_id: Optional[str] = None
    if baseline_result_path is not None:
        baseline_path = baseline_result_path.resolve(strict=True)
        if not _is_relative_to(baseline_path, artifacts_root):
            raise EvalSchemaError("--baseline-result escapes artifacts_root (fail-closed)")
        baseline = _require_json_object(baseline_path)
        baseline_result = baseline.get("result")
        if not isinstance(baseline_result, dict):
            raise EvalSchemaError("baseline missing result object (fail-closed)")
        if baseline_result.get("suite_hash") != suite.suite_hash:
            raise EvalSchemaError("baseline suite_hash mismatch (fail-closed)")
        if baseline_result.get("kernel_identity") != suite.kernel_identity:
            raise EvalSchemaError("baseline kernel_identity mismatch (fail-closed)")
        if not isinstance(baseline_result.get("run_id"), str):
            raise EvalSchemaError("baseline missing run_id (fail-closed)")
        baseline_run_id = str(baseline_result.get("run_id"))
        baseline_score = float(baseline_result.get("aggregate_score"))
        if baseline_score - aggregate_score > suite.regression_threshold:
            regression_flag = True

    result = BenchmarkResultSchema(
        run=run,
        per_case_scores=per_case_scores,
        aggregate_score=aggregate_score,
        regression_flag=regression_flag,
        provenance_refs=tuple(str(p) for p in epoch_manifest_paths),
    )

    if regression_flag:
        # Fail-closed: still write artifacts and ledger.
        status = "FAIL_CLOSED"
    else:
        status = "PASS"

    baseline_id = baseline_run_id if baseline_run_id is not None else run.run_id
    delta = LearningDeltaSchema.build(
        baseline_run_id=baseline_id,
        candidate_run_id=run.run_id,
        per_metric_deltas={"aggregate_score": aggregate_score - (baseline_score or aggregate_score)},
        confidence=1.0,
        suite_hash=suite.suite_hash,
        provenance_refs=[str(suite_path)],
    )
    reports_dir = artifacts_root / "eval_harness"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / f"benchmark_run_{run.run_id}.json"

    # Append-only, idempotent behavior:
    # If the report already exists for this deterministic run_id, re-validate it and do not write again.
    if report_path.exists():
        existing = _require_json_object(report_path)
        existing_result = existing.get("result")
        if not isinstance(existing_result, dict):
            raise EvalSchemaError("existing report missing result object (fail-closed)")
        if existing_result.get("run_id") != run.run_id or existing_result.get("suite_hash") != suite.suite_hash:
            raise EvalSchemaError("existing report identity mismatch (fail-closed)")
        if existing_result.get("kernel_identity") != suite.kernel_identity:
            raise EvalSchemaError("existing report kernel_identity mismatch (fail-closed)")
        if float(existing_result.get("aggregate_score")) != float(aggregate_score):
            raise EvalSchemaError("existing report aggregate_score mismatch (fail-closed)")
        # Do not append another delta ledger entry on rerun.
        return {
            "status": str(existing_result.get("status", status)),
            "run_id": run.run_id,
            "suite_hash": suite.suite_hash,
            "aggregate_score": aggregate_score,
            "regression_flag": bool(existing_result.get("regression_flag", regression_flag)),
            "report_path": str(report_path),
            "delta_id": delta.delta_id,
            "ledger_path": str(ledger_path),
            "idempotent_reuse": True,
        }

    delta_record = append_delta(ledger_path=ledger_path, delta=delta)
    write_report(
        report_path,
        result={
            "status": status,
            "run_id": run.run_id,
            "suite_hash": suite.suite_hash,
            "aggregate_score": aggregate_score,
            "per_case_scores": per_case_scores,
            "regression_flag": regression_flag,
            "regression_is_asymmetric": True,
            "kernel_identity": suite.kernel_identity,
        },
        deltas={"delta_id": delta.delta_id, "record_hash": delta_record["record_hash"]},
    )

    return {
        "status": status,
        "run_id": run.run_id,
        "suite_hash": suite.suite_hash,
        "aggregate_score": aggregate_score,
        "regression_flag": regression_flag,
        "report_path": str(report_path),
        "delta_id": delta.delta_id,
        "ledger_path": str(ledger_path),
    }


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="C023 Eval Harness (tooling-only)")
    p.add_argument("--suite", required=True, help="Benchmark suite JSON path")
    p.add_argument("--epoch-manifest", action="append", required=True, help="Epoch manifest JSON path(s)")
    p.add_argument("--run-record", action="append", required=True, help="Run record JSON path(s)")
    p.add_argument("--baseline-result", default="", help="Optional baseline result JSON path")
    p.add_argument("--artifacts-root", required=True, help="Artifacts root directory")
    p.add_argument("--delta-ledger", required=True, help="Delta ledger JSONL path")
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    summary = run_eval(
        suite_path=Path(args.suite),
        epoch_manifest_paths=[Path(p) for p in args.epoch_manifest],
        run_record_paths=[Path(p) for p in args.run_record],
        baseline_result_path=Path(args.baseline_result) if args.baseline_result else None,
        artifacts_root=Path(args.artifacts_root),
        ledger_path=Path(args.delta_ledger),
    )
    print(json.dumps(summary, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
