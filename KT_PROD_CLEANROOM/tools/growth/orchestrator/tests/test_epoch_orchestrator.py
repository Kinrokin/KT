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
from epoch_orchestrator import _precompute_run_id, _repo_root, _run_subprocess_capped, _write_once, run_epoch  # noqa: E402
from tools.growth.orchestrator.epoch_schemas import EpochPlan, EpochSchemaError  # noqa: E402
from checkpoint_store import append_checkpoint, completed_crucible_ids, CheckpointRecord  # noqa: E402
from crucible_loader import load_crucible  # noqa: E402


def _minimal_crucible(path: Path, *, kernel_targets: list[str] | None = None) -> None:
    if kernel_targets is None:
        kernel_targets = ["V2_SOVEREIGN"]
    if "V2_SOVEREIGN" not in kernel_targets:
        kernel_targets = ["V2_SOVEREIGN"] + list(kernel_targets)
    payload = {
        "schema": "kt.crucible.spec",
        "schema_version": 1,
        "crucible_id": "CRU-TEST-01",
        "title": "t",
        "domain": "d",
        "tags": {
            "domains": ["d"],
            "subdomains": [],
            "microdomains": [],
            "ventures": [],
            "reasoning_modes": [],
            "modalities": [],
            "tools": [],
            "paradox_classes": [],
        },
        "kernel_targets": kernel_targets,
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


def _minimal_plan(crucible_path: Path, *, kernel_target: str = "V2_SOVEREIGN", epoch_profile: str = "COVERAGE") -> dict:
    return {
        "epoch_id": "EPOCH-TEST-01",
        "epoch_profile": epoch_profile,
        "kernel_identity": {"kernel_target": kernel_target, "kernel_build_id": "unknown"},
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
            plan_path.write_text(
                json.dumps(_minimal_plan(crucible_path, epoch_profile="GOVERNANCE"), ensure_ascii=True),
                encoding="utf-8",
            )

            artifacts_root = td_path / "artifacts"
            epoch_root = artifacts_root / "EPOCH-TEST-01"
            run_dir = epoch_root / "CRU-TEST-01"
            run_dir.mkdir(parents=True, exist_ok=True)
            (run_dir / "run_record.json").write_text("{}", encoding="utf-8")

            checkpoint = epoch_root / "checkpoint.json"
            append_checkpoint(checkpoint, CheckpointRecord(crucible_id="CRU-TEST-01", run_id="X", outcome="PASS", status="DONE"))

            # materialize minimal per-run artifacts so coverage aggregation can succeed
            repo_root = _repo_root()
            run_root = repo_root / "tools" / "growth" / "artifacts" / "c019_runs" / "V2_SOVEREIGN" / "X"
            try:
                run_root.mkdir(parents=True, exist_ok=True)
                (run_root / "runner_record.json").write_text(json.dumps({"run_id": "X"}, ensure_ascii=True), encoding="utf-8")
                (run_root / "governance_verdict.json").write_text(
                    json.dumps({"schema_id": "governance.verdict", "schema_version": "1.0", "verdict": "PASS", "rationale": "test"}, ensure_ascii=True),
                    encoding="utf-8",
                )
                (run_root / "crucible_coverage.json").write_text(
                    json.dumps(
                        {
                            "schema_version": "COVERAGE_V1",
                            "run_id": "X",
                            "epoch_id": "EPOCH-TEST-01",
                            "crucible_id": "CRU-TEST-01",
                            "kernel_target": "V2_SOVEREIGN",
                            "planned": {"required_tags": [], "target_span": {"min_unique_domains": 0, "min_unique_subdomains": 0, "min_unique_microdomains": 0}, "rotation_ruleset_id": "ROTATION_RULESET_BOOTSTRAP_V1"},
                            "observed": {
                                "domains": ["D:TEST"],
                                "subdomains": ["S:TEST.SUB"],
                                "microdomains": ["M:TEST.SUB"],
                                "reasoning_modes": ["R:TEST"],
                                "modalities": ["X:TEXT"],
                                "tools": ["T:CRUCIBLE"],
                                "counts": {"unique_domains": 1, "unique_subdomains": 1, "unique_microdomains": 1, "cross_domain_edges": 0, "mean_graph_distance": 0, "max_graph_distance": 0, "paradox_events": 0},
                                "dominance": {"top_domain_share": 1.0, "top_5_domain_share": 1.0, "entropy_domains": 0.0},
                            },
                            "sequence": ["D:TEST"],
                            "proof": {
                                "receipts": [
                                    {"type": "TRACE_HEAD_HASH", "sha256": "0" * 64},
                                    {"type": "LEDGER_ENTRY_HASH", "sha256": "0" * 64},
                                ],
                                "fail_closed": True,
                            },
                            "verdict": {"coverage_pass": None, "rotation_pass": None, "notes": None},
                        },
                        ensure_ascii=True,
                    ),
                    encoding="utf-8",
                )
                (run_root / "_runtime_artifacts").mkdir(parents=True, exist_ok=True)
                (run_root / "_runtime_artifacts" / "state_vault.jsonl").write_text("{\"organ_id\":\"TEST\"}\n", encoding="utf-8")

                summary = run_epoch(plan_path, resume=True, artifacts_root=artifacts_root)
                self.assertEqual(summary["epoch_id"], "EPOCH-TEST-01")
                self.assertTrue((epoch_root / "epoch_summary.json").exists())
            finally:
                if run_root.exists():
                    for p in sorted(run_root.rglob("*"), reverse=True):
                        if p.is_file():
                            p.unlink()
                        else:
                            p.rmdir()
                if run_root.parent.exists() and not any(run_root.parent.iterdir()):
                    run_root.parent.rmdir()


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
        if os.name == "nt":
            self.skipTest("Memory cap enforcement not reliable on Windows")
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

            with self.assertRaises(EpochSchemaError):
                run_epoch(plan_path, resume=False, artifacts_root=artifacts_root, runner_cmd_override=runner_override)


class TestKernelTargetRouting(unittest.TestCase):
    def test_kernel_target_from_plan_used_for_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            crucible_path = td_path / "c.json"
            _minimal_crucible(
                crucible_path,
                kernel_targets=["KERNEL_GOVERNANCE_BASELINE"],
            )
            plan_path = td_path / "epoch.json"
            plan_path.write_text(
                json.dumps(_minimal_plan(crucible_path, kernel_target="KERNEL_GOVERNANCE_BASELINE", epoch_profile="GOVERNANCE"), ensure_ascii=True),
                encoding="utf-8",
            )

            artifacts_root = td_path / "artifacts"

            loaded = load_crucible(crucible_path)
            expected_run_id = _precompute_run_id(
                crucible_spec=loaded.spec,
                crucible_spec_hash_hex=loaded.crucible_spec_hash,
                budgets=loaded.spec.budgets,
                kernel_target="KERNEL_GOVERNANCE_BASELINE",
                seed=0,
            )

            repo_root = _repo_root()
            run_root = repo_root / "tools" / "growth" / "artifacts" / "c019_runs" / "KERNEL_GOVERNANCE_BASELINE" / expected_run_id
            other_root = repo_root / "tools" / "growth" / "artifacts" / "c019_runs" / "KERNEL_COVERAGE_BASELINE" / expected_run_id

            def runner_override(_crucible_path: Path, kernel_target: str, _seed: int):
                script_lines = [
                    "import json",
                    "from pathlib import Path",
                    f"run_root = Path(r\"{run_root}\")",
                    "run_root.mkdir(parents=True, exist_ok=True)",
                    "run_root.joinpath('runner_record.json').write_text(" +
                    "json.dumps({" +
                    f"'run_id':'{expected_run_id}','crucible_id':'CRU-TEST-01','kernel_target':'{kernel_target}','outcome':'PASS'" +
                    "}, ensure_ascii=True), encoding='utf-8')",
                    "run_root.joinpath('governance_verdict.json').write_text(" +
                    "json.dumps({" +
                    "'schema_id':'governance.verdict','schema_version':'1.0','verdict':'PASS','rationale':'test'" +
                    "}, ensure_ascii=True), encoding='utf-8')",
                    "run_root.joinpath('crucible_coverage.json').write_text(" +
                    "json.dumps({" +
                    f"'schema_version':'COVERAGE_V1','run_id':'{expected_run_id}','epoch_id':'EPOCH-TEST-01','crucible_id':'CRU-TEST-01','kernel_target':'{kernel_target}'," +
                    "'planned':{'required_tags':[],'target_span':{'min_unique_domains':0,'min_unique_subdomains':0,'min_unique_microdomains':0},'rotation_ruleset_id':'ROTATION_RULESET_BOOTSTRAP_V1'}," +
                    "'observed':{'domains':['D:TEST'],'subdomains':['S:TEST.SUB'],'microdomains':['M:TEST.SUB'],'reasoning_modes':['R:TEST'],'modalities':['X:TEXT'],'tools':['T:CRUCIBLE']," +
                    "'counts':{'unique_domains':1,'unique_subdomains':1,'unique_microdomains':1,'cross_domain_edges':0,'mean_graph_distance':0,'max_graph_distance':0,'paradox_events':0}," +
                    "'dominance':{'top_domain_share':1.0,'top_5_domain_share':1.0,'entropy_domains':0.0}}," +
                    "'sequence':['D:TEST']," +
                    "'proof':{'receipts':[{'type':'TRACE_HEAD_HASH','sha256':'" + ("0"*64) + "'},{'type':'LEDGER_ENTRY_HASH','sha256':'" + ("0"*64) + "'}],'fail_closed':True}," +
                    "'verdict':{'coverage_pass':None,'rotation_pass':None,'notes':None}" +
                    "}, ensure_ascii=True), encoding='utf-8')",
                    "run_root.joinpath('micro_steps.json').write_text(" +
                    "json.dumps({" +
                    f"'schema':'MICRO_STEPS_V1','run_id':'{expected_run_id}','crucible_id':'CRU-TEST-01','kernel_target':'{kernel_target}','steps':[]" +
                    "}, ensure_ascii=True), encoding='utf-8')",
                    "runtime_artifacts = run_root / '_runtime_artifacts'",
                    "runtime_artifacts.mkdir(parents=True, exist_ok=True)",
                    "runtime_artifacts.joinpath('state_vault.jsonl').write_text('{\"organ_id\":\"TEST\"}\\n', encoding='utf-8')",
                    f"print(json.dumps([{{'run_id':'{expected_run_id}','outcome':'PASS'}}], ensure_ascii=True))",
                ]
                script = "\n".join(script_lines)
                return [sys.executable, '-c', script], repo_root

            try:
                summary = run_epoch(plan_path, resume=False, artifacts_root=artifacts_root, runner_cmd_override=runner_override)
                self.assertEqual(summary["runs"][0]["outcome"], "PASS")
                self.assertTrue(run_root.exists())
                self.assertFalse(other_root.exists())
            finally:
                if run_root.exists():
                    for p in sorted(run_root.rglob("*"), reverse=True):
                        if p.is_file():
                            p.unlink()
                        else:
                            p.rmdir()
                if run_root.parent.exists() and not any(run_root.parent.iterdir()):
                    run_root.parent.rmdir()


if __name__ == "__main__":
    raise SystemExit(unittest.main())
