from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import sys


def _add_growth_to_syspath() -> None:
    # .../tools/growth/orchestrator/tests/test_epoch_orchestrator.py -> .../tools/growth/orchestrator
    orchestrator_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(orchestrator_root))
    # Crucible loader lives under tools/growth/crucibles
    crucibles_root = orchestrator_root.parent / "crucibles"
    sys.path.insert(0, str(crucibles_root))


_add_growth_to_syspath()

from epoch_manifest import compute_epoch_hash  # noqa: E402
from epoch_orchestrator import _run_subprocess_capped, _write_once, run_epoch  # noqa: E402
from epoch_schemas import EpochPlan, EpochSchemaError  # noqa: E402
from checkpoint_store import append_checkpoint, completed_crucible_ids, CheckpointRecord  # noqa: E402


def _minimal_crucible(path: Path) -> None:
    payload = {
        "schema": "kt.crucible.spec",
        "schema_version": 1,
        "crucible_id": "CRU-TEST-01",
        "title": "t",
        "domain": "d",
        "kernel_targets": ["V2_SOVEREIGN"],
        "input": {"mode": "RAW_INPUT_STRING", "prompt": "x", "redaction_policy": "ALLOW_RAW_IN_CRUCIBLE"},
        "budgets": {"time_ms": 1000},
        "expect": {
            "expected_outcome": "PASS",
            "output_contract": {"must_be_json": True, "required_keys": []},
            "replay_verification": "NOT_APPLICABLE",
            "governance_expectations": {"required_event_types": [], "forbidden_event_types": [], "event_count_min": 0, "event_count_max": 0},
            "thermo_expectations": {"must_enforce_budget": False, "expected_budget_verdict": "BUDGET_NOT_ASSERTED"},
        },
    }
    path.write_text(json.dumps(payload, ensure_ascii=True), encoding="utf-8")


def _minimal_plan(crucible_path: Path) -> dict:
    return {
        "epoch_id": "EPOCH-TEST-01",
        "kernel_identity": {"kernel_target": "V2_SOVEREIGN", "kernel_build_id": "unknown"},
        "crucible_order": ["CRU-TEST-01"],
        "crucible_specs": {"CRU-TEST-01": str(crucible_path)},
        "budgets": {"per_crucible_timeout_ms": 1000, "per_crucible_rss_mb": 1024, "epoch_wall_clock_ms": 10000, "max_concurrency": 1},
        "runner_config": {"template_id": "C019_RUNNER_V1", "args": []},
        "stop_conditions": {"max_failures": 0},
        "seed": 0,
    }


class TestEpochDeterminism(unittest.TestCase):
    def test_epoch_hash_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            crucible_path = Path(td) / "c.json"
            _minimal_crucible(crucible_path)
            plan = EpochPlan.from_dict(_minimal_plan(crucible_path))
            spec_hashes = {"CRU-TEST-01": "abc" * 21 + "ab"}
            a = compute_epoch_hash(plan, crucible_spec_hashes=spec_hashes)
            b = compute_epoch_hash(plan, crucible_spec_hashes=spec_hashes)
            self.assertEqual(a, b)


class TestCheckpoint(unittest.TestCase):
    def test_checkpoint_completed_ids(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "checkpoint.json"
            append_checkpoint(path, CheckpointRecord(crucible_id="A", run_id="1", outcome="PASS", status="DONE"))
            append_checkpoint(path, CheckpointRecord(crucible_id="B", run_id="2", outcome="FAIL", status="DONE"))
            done = completed_crucible_ids(path)
            self.assertEqual(done, {"A", "B"})


class TestResumeBehavior(unittest.TestCase):
    def test_resume_skips_completed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            crucible_path = td_path / "c.json"
            _minimal_crucible(crucible_path)
            plan_path = td_path / "epoch.json"
            plan_path.write_text(json.dumps(_minimal_plan(crucible_path), ensure_ascii=True), encoding="utf-8")

            artifacts_root = td_path / "artifacts"
            epoch_root = artifacts_root / "EPOCH-TEST-01"
            run_dir = epoch_root / "CRU-TEST-01"
            run_dir.mkdir(parents=True, exist_ok=True)
            (run_dir / "run_record.json").write_text("{}", encoding="utf-8")

            checkpoint = epoch_root / "checkpoint.json"
            append_checkpoint(checkpoint, CheckpointRecord(crucible_id="CRU-TEST-01", run_id="X", outcome="PASS", status="DONE"))

            summary = run_epoch(plan_path, resume=True, artifacts_root=artifacts_root)
            self.assertEqual(summary["epoch_id"], "EPOCH-TEST-01")
            self.assertTrue((epoch_root / "epoch_summary.json").exists())


class TestRunnerCaps(unittest.TestCase):
    def test_timeout_kills_process_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cwd = Path(td)
            cmd = [sys.executable, "-c", "import time; time.sleep(10)"]
            res = _run_subprocess_capped(
                command=cmd,
                cwd=cwd,
                env=dict(os.environ),
                time_ms=50,
                kill_grace_ms=100,
                stdout_max_bytes=1024,
                stderr_max_bytes=1024,
                memory_max_mb=256,
            )
            self.assertTrue(res.was_killed)
            self.assertEqual(res.kill_reason, "TIMEOUT")

    def test_memory_limit_kills_process_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cwd = Path(td)
            cmd = [sys.executable, "-c", "x = bytearray(128 * 1024 * 1024)\nprint('x')\n"]
            res = _run_subprocess_capped(
                command=cmd,
                cwd=cwd,
                env=dict(os.environ),
                time_ms=5_000,
                kill_grace_ms=5_100,
                stdout_max_bytes=1024,
                stderr_max_bytes=1024,
                memory_max_mb=32,
            )
            self.assertTrue(res.was_killed)
            self.assertEqual(res.kill_reason, "MEMORY_LIMIT")


class TestAppendOnly(unittest.TestCase):
    def test_write_once_rejects_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "file.txt"
            p.write_text("first", encoding="utf-8")
            with self.assertRaises(EpochSchemaError):
                _write_once(p, "second")


class TestNonJsonOutput(unittest.TestCase):
    def test_non_json_stdout_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            crucible_path = td_path / "c.json"
            _minimal_crucible(crucible_path)
            plan_path = td_path / "epoch.json"
            plan_path.write_text(json.dumps(_minimal_plan(crucible_path), ensure_ascii=True), encoding="utf-8")

            artifacts_root = td_path / "artifacts"

            def runner_override(_crucible_path: Path, _kernel_target: str, _seed: int):
                cmd = [sys.executable, "-c", "print('not json')"]
                return cmd, td_path

            summary = run_epoch(plan_path, resume=False, artifacts_root=artifacts_root, runner_cmd_override=runner_override)
            self.assertEqual(summary["runs"][0]["outcome"], "FAIL_CLOSED")


if __name__ == "__main__":
    raise SystemExit(unittest.main())
