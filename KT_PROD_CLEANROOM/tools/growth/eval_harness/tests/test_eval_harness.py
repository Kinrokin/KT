from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import sys


def _add_eval_to_syspath() -> None:
    # .../tools/growth/eval_harness/tests/test_eval_harness.py -> .../tools/growth/eval_harness
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))


_add_eval_to_syspath()

from eval_runner import run_eval  # noqa: E402


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True, ensure_ascii=True), encoding="utf-8")


def _make_run_dir(base: Path, *, run_id: str, crucible_id: str, kernel_target: str = "V2_SOVEREIGN") -> Path:
    run_dir = base / "c019_runs" / kernel_target / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    _write_json(
        run_dir / "runner_record.json",
        {
            "run_id": run_id,
            "crucible_id": crucible_id,
            "kernel_target": kernel_target,
            "outcome": "PASS",
            "replay_pass": True,
            "governance_pass": True,
        },
    )
    _write_json(run_dir / "governance_report.json", {"count": 1, "types": ["GOV_POLICY_APPLY"]})
    _write_json(run_dir / "replay_report.json", {"status": "PASS", "record_count": 1, "head_hash": "a" * 64})
    return run_dir


def _suite_payload(*, input_refs: list[str], kernel_target: str = "V2_SOVEREIGN") -> dict:
    return {
        "suite_id": "SUITE-1",
        "suite_version": 1,
        "kernel_identity": {"kernel_target": kernel_target, "kernel_build_id": "unknown"},
        "regression_threshold": 0.0,
        "cases": [
            {
                "case_id": "CASE-1",
                "domain": "governance",
                "objective": "pass rate is 1.0",
                "input_refs": input_refs,
                "expected_metrics": {"pass_rate": 1.0},
                "metric_weights": {"pass_rate": 1.0},
                "bounds": {"max_inputs": 16, "max_outputs": 16},
                "provenance_refs": [],
            }
        ],
    }


class TestEvalHarness(unittest.TestCase):
    def test_input_refs_must_be_under_artifacts_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            artifacts_root = root / "artifacts"
            artifacts_root.mkdir()

            epoch_manifest = root / "epoch_manifest.json"
            _write_json(
                epoch_manifest,
                {"epoch_id": "E1", "kernel_identity": {"kernel_target": "V2_SOVEREIGN", "kernel_build_id": "unknown"}},
            )

            run_dir = _make_run_dir(artifacts_root, run_id="r" * 64, crucible_id="C1")
            outside = root / "outside" / "runner_record.json"
            outside.parent.mkdir(parents=True, exist_ok=True)
            _write_json(outside, {"crucible_id": "C1", "outcome": "PASS"})

            suite_path = root / "suite.json"
            _write_json(suite_path, _suite_payload(input_refs=[str(outside)]))

            with self.assertRaises(Exception):
                run_eval(
                    suite_path=suite_path,
                    epoch_manifest_paths=[epoch_manifest],
                    run_record_paths=[run_dir / "runner_record.json"],
                    baseline_result_path=None,
                    artifacts_root=artifacts_root,
                    ledger_path=artifacts_root / "delta.jsonl",
                )

    def test_kernel_identity_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            artifacts_root = root / "artifacts"
            artifacts_root.mkdir()

            run_dir = _make_run_dir(artifacts_root, run_id="r" * 64, crucible_id="C1", kernel_target="V2_SOVEREIGN")
            suite_path = root / "suite.json"
            _write_json(suite_path, _suite_payload(input_refs=[str((run_dir / "runner_record.json").relative_to(artifacts_root))], kernel_target="V1_ARCHIVAL"))

            epoch_manifest = root / "epoch_manifest.json"
            _write_json(
                epoch_manifest,
                {"epoch_id": "E1", "kernel_identity": {"kernel_target": "V1_ARCHIVAL", "kernel_build_id": "unknown"}},
            )

            with self.assertRaises(Exception):
                run_eval(
                    suite_path=suite_path,
                    epoch_manifest_paths=[epoch_manifest],
                    run_record_paths=[run_dir / "runner_record.json"],
                    baseline_result_path=None,
                    artifacts_root=artifacts_root,
                    ledger_path=artifacts_root / "delta.jsonl",
                )

    def test_baseline_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            artifacts_root = root / "artifacts"
            artifacts_root.mkdir()

            run_dir = _make_run_dir(artifacts_root, run_id="r" * 64, crucible_id="C1")
            suite_path = root / "suite.json"
            _write_json(suite_path, _suite_payload(input_refs=[str((run_dir / "runner_record.json").relative_to(artifacts_root))]))

            epoch_manifest = root / "epoch_manifest.json"
            _write_json(
                epoch_manifest,
                {"epoch_id": "E1", "kernel_identity": {"kernel_target": "V2_SOVEREIGN", "kernel_build_id": "unknown"}},
            )

            baseline_report = artifacts_root / "eval_harness" / "baseline.json"
            _write_json(
                baseline_report,
                {
                    "result": {
                        "status": "PASS",
                        "run_id": "baseline",
                        "suite_hash": "b" * 64,
                        "aggregate_score": 1.0,
                        "kernel_identity": {"kernel_target": "V2_SOVEREIGN", "kernel_build_id": "unknown"},
                    },
                    "deltas": {},
                },
            )

            with self.assertRaises(Exception):
                run_eval(
                    suite_path=suite_path,
                    epoch_manifest_paths=[epoch_manifest],
                    run_record_paths=[run_dir / "runner_record.json"],
                    baseline_result_path=baseline_report,
                    artifacts_root=artifacts_root,
                    ledger_path=artifacts_root / "delta.jsonl",
                )


if __name__ == "__main__":
    raise SystemExit(unittest.main())
