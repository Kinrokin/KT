from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from unittest.mock import patch
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
from epoch_orchestrator import _default_salvage_root, _precompute_run_id, _repo_root, _run_subprocess_capped, _write_once, preflight_epoch, run_epoch  # noqa: E402
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


class TestArtifactsRootOverride(unittest.TestCase):
    def test_explicit_epoch_root_selects_sibling_salvage_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            epoch_root = Path(td) / "explicit" / "epochs"
            self.assertEqual(_default_salvage_root(epoch_root), Path(td) / "explicit" / "salvage")

    def test_autonomous_analyzer_rejects_log_epoch_escape(self) -> None:
        from tools.growth import analyze_autonomous_run

        with tempfile.TemporaryDirectory() as td:
            growth_root = Path(td) / "growth"
            outside = growth_root / "outside"
            outside.mkdir(parents=True)
            (outside / "epoch_summary.json").write_text('{"runs": []}', encoding="utf-8")
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}):
                with self.assertRaisesRegex(ValueError, "unsafe_epoch_path_component"):
                    analyze_autonomous_run.duration_stats(
                        [{"epoch": "../outside", "plan_run": "coverage"}]
                    )

    def test_autonomous_analyzer_rejects_log_run_id_escape(self) -> None:
        from tools.growth import analyze_autonomous_run

        with tempfile.TemporaryDirectory() as td:
            growth_root = Path(td) / "growth"
            epoch = growth_root / "epochs" / "EPOCH-SAFE"
            epoch.mkdir(parents=True)
            (epoch / "epoch_summary.json").write_text(
                json.dumps({"runs": [{"run_id": "../../outside"}]}),
                encoding="utf-8",
            )
            (growth_root / "c019_runs" / "KERNEL").mkdir(parents=True)
            outside = growth_root / "outside"
            outside.mkdir()
            (outside / "runner_record.json").write_text(
                json.dumps({"duration_ms": 999}), encoding="utf-8"
            )
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}):
                with self.assertRaisesRegex(ValueError, "unsafe_run_id_path_component"):
                    analyze_autonomous_run.duration_stats(
                        [{"epoch": "EPOCH-SAFE", "plan_run": "coverage"}]
                    )

    def test_escalation_analyzer_rejects_log_epoch_escape(self) -> None:
        from tools.growth import analyze_escalation

        with tempfile.TemporaryDirectory() as td:
            growth_root = Path(td) / "growth"
            log_path = growth_root / "logs" / "epoch_escalation_log.json"
            log_path.parent.mkdir(parents=True)
            log_path.write_text(
                json.dumps([{"epoch": "../outside", "plan": "next", "bad": False}]),
                encoding="utf-8",
            )
            outside = growth_root / "outside"
            outside.mkdir()
            (outside / "epoch_summary.json").write_text("{}", encoding="utf-8")
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}):
                with self.assertRaisesRegex(ValueError, "unsafe_epoch_path_component"):
                    analyze_escalation.run()

    def test_relative_override_has_one_cleanroom_base(self) -> None:
        from epoch_orchestrator import _growth_artifacts_root
        from tools.growth import analyze_autonomous_run, analyze_escalation, e2e_gate
        from tools.growth.state import (
            analyze_policy_shadow,
            cce_state,
            compute_epoch_regret,
            oce_state,
            plan_suggester,
            rwrp_state,
        )

        relative = Path("relative-growth-root")
        expected = (_repo_root() / relative).resolve()
        with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(relative)}):
            self.assertEqual(_growth_artifacts_root(), expected)
            self.assertEqual(e2e_gate._epoch_artifacts_root(), expected / "epochs")
            self.assertEqual(e2e_gate._salvage_root(), expected / "salvage")
            self.assertEqual(analyze_autonomous_run._growth_artifacts_root(), expected)
            self.assertEqual(analyze_escalation._growth_artifacts_root(), expected)
            self.assertEqual(analyze_policy_shadow._growth_artifacts_root(), expected)
            self.assertEqual(compute_epoch_regret._growth_artifacts_root(), expected)
            self.assertEqual(plan_suggester._growth_artifacts_root(), expected)
            self.assertEqual(cce_state._state_path().parents[1], expected)
            self.assertEqual(oce_state._state_path().parents[1], expected)
            self.assertEqual(rwrp_state._state_path().parents[1], expected)

    def test_escalation_consumers_share_external_epochs_root(self) -> None:
        from tools.growth import run_autonomous_escalation, run_epoch_escalation

        with tempfile.TemporaryDirectory() as td:
            override_root = Path(td) / "external growth"
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(override_root)}):
                expected = (override_root / "epochs").resolve()
                self.assertEqual(run_epoch_escalation._artifact_epochs_root(), expected)
                self.assertEqual(run_autonomous_escalation._artifact_epochs_root(), expected)

    def test_escalation_consumers_route_all_mutable_outputs_external(self) -> None:
        from tools.growth import (
            analyze_autonomous_run,
            analyze_escalation,
            run_autonomous_escalation,
            run_epoch_escalation,
        )
        from tools.growth.state import analyze_policy_shadow

        with tempfile.TemporaryDirectory() as td:
            override_root = (Path(td) / "external growth").resolve()
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(override_root)}):
                self.assertEqual(run_autonomous_escalation._artifact_state_root(), override_root / "state")
                self.assertEqual(
                    run_autonomous_escalation._plan_suggestions_ledger_path(),
                    override_root / "state" / "plan_suggestions.jsonl",
                )
                self.assertEqual(
                    run_autonomous_escalation._autonomous_log_path(),
                    override_root / "logs" / "autonomous_escalation_log.json",
                )
                self.assertEqual(
                    run_epoch_escalation._epoch_escalation_log_path(),
                    override_root / "logs" / "epoch_escalation_log.json",
                )
                self.assertEqual(analyze_autonomous_run._autonomous_log_path(), override_root / "logs" / "autonomous_escalation_log.json")
                self.assertEqual(analyze_autonomous_run._artifact_epochs_root(), override_root / "epochs")
                self.assertEqual(analyze_autonomous_run._c019_runs_root(), override_root / "c019_runs")
                self.assertEqual(analyze_autonomous_run._analysis_path(), override_root / "reports" / "autonomous_analysis.json")
                self.assertEqual(analyze_escalation._artifact_epochs_root(), override_root / "epochs")
                self.assertEqual(analyze_escalation._epoch_escalation_log_path(), override_root / "logs" / "epoch_escalation_log.json")
                self.assertEqual(
                    analyze_policy_shadow._default_policy_log_path(),
                    override_root / "state" / "lane_policy_comparison.jsonl",
                )

    def test_plan_suggester_and_analyzer_share_external_policy_log(self) -> None:
        from tools.growth.state import analyze_policy_shadow, plan_suggester

        with tempfile.TemporaryDirectory() as td:
            override_root = (Path(td) / "external growth").resolve()
            expected = override_root / "state" / "lane_policy_comparison.jsonl"
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(override_root)}):
                self.assertEqual(plan_suggester._default_policy_log_path(), expected)
                self.assertEqual(analyze_policy_shadow._default_policy_log_path(), expected)

    def test_cce_default_state_is_outside_registered_source_state(self) -> None:
        from tools.growth.state import cce_state

        expected = cce_state._CLEANROOM_ROOT / "tools" / "growth" / "artifacts" / "state" / "cce_state.json"
        with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": ""}):
            self.assertEqual(cce_state._state_path(), expected)
            self.assertNotEqual(cce_state._state_path(), cce_state._STATE_PATH)

    def test_oce_default_state_is_outside_registered_source_state(self) -> None:
        from tools.growth.state import oce_state

        expected = oce_state._CLEANROOM_ROOT / "tools" / "growth" / "artifacts" / "state" / "oce_state.json"
        with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": ""}):
            self.assertEqual(oce_state._state_path(), expected)
            self.assertNotEqual(oce_state._state_path(), oce_state._STATE_PATH)

    def test_rwrp_default_state_is_outside_registered_source_state(self) -> None:
        from tools.growth.state import rwrp_state

        expected = rwrp_state._CLEANROOM_ROOT / "tools" / "growth" / "artifacts" / "state" / "rwrp_state.json"
        with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": ""}):
            self.assertEqual(rwrp_state._state_path(), expected)
            self.assertNotEqual(rwrp_state._state_path(), rwrp_state._STATE_PATH)

    def test_plan_suggester_append_default_uses_growth_artifacts_state(self) -> None:
        from tools.growth.state import plan_suggester

        expected = plan_suggester._CLEANROOM_ROOT / "tools" / "growth" / "artifacts" / "state" / "plan_suggestions.jsonl"
        with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": ""}):
            self.assertEqual(plan_suggester._default_suggestions_log_path(), expected)

    def test_epoch_regret_default_uses_growth_artifacts_epochs(self) -> None:
        from tools.growth.state import compute_epoch_regret

        expected = compute_epoch_regret._CLEANROOM_ROOT / "tools" / "growth" / "artifacts" / "epochs"
        with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": ""}):
            self.assertEqual(compute_epoch_regret._default_epochs_dir(), expected)

    def test_plan_suggester_uses_explicit_external_ledger(self) -> None:
        from tools.growth import run_autonomous_escalation

        with tempfile.TemporaryDirectory() as td:
            override_root = (Path(td) / "external growth").resolve()
            epoch_root = override_root / "epochs" / "EPOCH-SUGGESTED-RUN1"
            observed = {}

            def fake_run(command, *, env, check):
                observed["command"] = list(command)
                observed["env"] = dict(env)
                observed["check"] = check
                epoch_root.mkdir(parents=True)
                (epoch_root / "plan_suggestion.json").write_text(
                    json.dumps({"status": "PASS"}), encoding="utf-8"
                )

            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(override_root)}), patch.object(
                run_autonomous_escalation.subprocess, "run", side_effect=fake_run
            ):
                result = run_autonomous_escalation.run_plan_suggester()

            command = observed["command"]
            self.assertEqual(result, {"status": "PASS"})
            self.assertTrue(observed["check"])
            self.assertNotIn("--append-log", command)
            self.assertEqual(
                command[command.index("--ledger-out") + 1],
                str(override_root / "state" / "plan_suggestions.jsonl"),
            )
            self.assertEqual(
                command[command.index("--epochs-dir") + 1],
                str(override_root / "epochs"),
            )

    def test_growth_state_updates_preserve_repository_state_files(self) -> None:
        from tools.growth.state import cce_state, oce_state, rwrp_state

        modules = (cce_state, oce_state, rwrp_state)
        source_before = {
            module._STATE_PATH: module._STATE_PATH.read_bytes() if module._STATE_PATH.exists() else None
            for module in modules
        }
        with tempfile.TemporaryDirectory() as td:
            override_root = (Path(td) / "external growth").resolve()
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(override_root)}):
                cce_state.update_state(executed_lane="COVERAGE_HOP_RECOVERY", epoch_id="EPOCH-EXTERNAL-STATE")
                oce_state.update_state(executed_lane="COVERAGE_HOP_RECOVERY", epoch_id="EPOCH-EXTERNAL-STATE")
                rwrp_state.update_state(
                    executed_lane="COVERAGE_HOP_RECOVERY",
                    epoch_id="EPOCH-EXTERNAL-STATE",
                    regret_global=0.25,
                )
                for module in modules:
                    state_path = module._state_path()
                    self.assertEqual(state_path.parent, override_root / "state")
                    self.assertTrue(state_path.is_file())
                    payload = json.loads(state_path.read_text(encoding="utf-8"))
                    self.assertEqual(payload["updated_at_epoch_id"], "EPOCH-EXTERNAL-STATE")

        for path, original in source_before.items():
            if original is None:
                self.assertFalse(path.exists())
            else:
                self.assertEqual(path.read_bytes(), original)

    def test_preflight_uses_external_collision_history_and_explicit_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            crucible_path = root / "c.json"
            _minimal_crucible(crucible_path, kernel_targets=["KERNEL_GOVERNANCE_BASELINE"])
            plan = _minimal_plan(crucible_path, kernel_target="KERNEL_GOVERNANCE_BASELINE", epoch_profile="GOVERNANCE")
            plan["epoch_id"] = "EPOCH-EXTERNAL-PREFLIGHT_RUN1"
            plan_path = root / "epoch.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            artifacts_root = root / "external growth"
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(artifacts_root)}):
                self.assertEqual(preflight_epoch(plan_path, resume=False, artifacts_root=None, auto_bump=False), 0)
                occupied = artifacts_root / "epochs" / plan["epoch_id"]
                occupied.mkdir(parents=True)
                sentinel = occupied / "epoch_manifest.json"
                sentinel.write_text("{}", encoding="utf-8")
                self.assertEqual(preflight_epoch(plan_path, resume=False, artifacts_root=None, auto_bump=False), 2)
                self.assertEqual(preflight_epoch(plan_path, resume=False, artifacts_root=root / "explicit epochs", auto_bump=False), 0)
                self.assertEqual(sentinel.read_text(encoding="utf-8"), "{}")
                self.assertEqual(set(artifacts_root.rglob("*")), {artifacts_root / "epochs", occupied, sentinel})

    def test_preflight_rejects_epoch_ids_that_can_escape_or_alias_the_artifact_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            crucible_path = root / "c.json"
            _minimal_crucible(crucible_path, kernel_targets=["KERNEL_GOVERNANCE_BASELINE"])
            artifacts_root = root / "external growth"
            plan_path = root / "epoch.json"
            for epoch_id in (
                "../outside",
                "/absolute/outside",
                "nested/outside",
                "nested\\outside",
                ".",
                "..",
                "EPOCH-TRAILING.",
                "CON",
                "nul.json",
                "Com1.log",
                "LPT9",
            ):
                plan = _minimal_plan(
                    crucible_path,
                    kernel_target="KERNEL_GOVERNANCE_BASELINE",
                    epoch_profile="GOVERNANCE",
                )
                plan["epoch_id"] = epoch_id
                plan_path.write_text(json.dumps(plan), encoding="utf-8")
                with self.assertRaisesRegex(EpochSchemaError, "portable direct path component"):
                    preflight_epoch(plan_path, resume=False, artifacts_root=artifacts_root, auto_bump=False)
                self.assertFalse(artifacts_root.exists(), epoch_id)

    def test_env_override_routes_c019_epochs_and_salvage_under_override_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            crucible_path = td_path / "c.json"
            _minimal_crucible(crucible_path, kernel_targets=["KERNEL_GOVERNANCE_BASELINE"])
            plan_path = td_path / "epoch.json"
            plan_path.write_text(
                json.dumps(
                    _minimal_plan(
                        crucible_path,
                        kernel_target="KERNEL_GOVERNANCE_BASELINE",
                        epoch_profile="GOVERNANCE",
                    ),
                    ensure_ascii=True,
                ),
                encoding="utf-8",
            )

            override_root = td_path / "growth_artifacts"
            previous_override = os.environ.get("KT_GROWTH_ARTIFACTS_ROOT")
            os.environ["KT_GROWTH_ARTIFACTS_ROOT"] = override_root.as_posix()
            try:
                loaded = load_crucible(crucible_path)
                expected_run_id = _precompute_run_id(
                    crucible_spec=loaded.spec,
                    crucible_spec_hash_hex=loaded.crucible_spec_hash,
                    budgets=loaded.spec.budgets,
                    kernel_target="KERNEL_GOVERNANCE_BASELINE",
                    seed=0,
                )

                def runner_override(_crucible_path: Path, kernel_target: str, _seed: int):
                    run_root = override_root / "c019_runs" / kernel_target / expected_run_id
                    run_root.mkdir(parents=True, exist_ok=True)
                    (run_root / "runner_record.json").write_text(
                        json.dumps({"run_id": expected_run_id}, ensure_ascii=True),
                        encoding="utf-8",
                    )
                    (run_root / "governance_verdict.json").write_text(
                        json.dumps(
                            {"schema_id": "governance.verdict", "schema_version": "1.0", "verdict": "PASS", "rationale": "test"},
                            ensure_ascii=True,
                        ),
                        encoding="utf-8",
                    )
                    (run_root / "crucible_coverage.json").write_text(
                        json.dumps(
                            {
                                "schema_version": "COVERAGE_V1",
                                "run_id": expected_run_id,
                                "epoch_id": "EPOCH-TEST-01",
                                "crucible_id": "CRU-TEST-01",
                                "kernel_target": kernel_target,
                                "planned": {
                                    "required_tags": [],
                                    "target_span": {"min_unique_domains": 0, "min_unique_subdomains": 0, "min_unique_microdomains": 0},
                                    "rotation_ruleset_id": "ROTATION_RULESET_BOOTSTRAP_V1",
                                },
                                "observed": {
                                    "domains": ["D:TEST"],
                                    "subdomains": ["S:TEST.SUB"],
                                    "microdomains": ["M:TEST.SUB"],
                                    "reasoning_modes": ["R:TEST"],
                                    "modalities": ["X:TEXT"],
                                    "tools": ["T:CRUCIBLE"],
                                    "counts": {
                                        "unique_domains": 1,
                                        "unique_subdomains": 1,
                                        "unique_microdomains": 1,
                                        "cross_domain_edges": 0,
                                        "mean_graph_distance": 0,
                                        "max_graph_distance": 0,
                                        "paradox_events": 0,
                                    },
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
                    runtime = run_root / "_runtime_artifacts"
                    runtime.mkdir(parents=True, exist_ok=True)
                    (runtime / "state_vault.jsonl").write_text("{\"organ_id\":\"TEST\"}\n", encoding="utf-8")
                    script = f"import json; print(json.dumps([{{'run_id':'{expected_run_id}','outcome':'PASS'}}]))"
                    return [sys.executable, "-c", script], td_path

                summary = run_epoch(plan_path, resume=False, runner_cmd_override=runner_override, salvage=True)
                epoch_root = override_root / "epochs" / summary["epoch_id"]
                self.assertTrue((epoch_root / "epoch_manifest.json").is_file())
                salvage_status = json.loads((epoch_root / "salvage_status.json").read_text(encoding="utf-8"))
                self.assertEqual(salvage_status["status"], "OK", salvage_status)
                salvage_root = override_root / "salvage" / summary["epoch_id"]
                self.assertEqual(Path(salvage_status["out"]).resolve(), salvage_root.resolve())
                manifest = json.loads((salvage_root / "salvage_manifest.json").read_text(encoding="utf-8"))
                for output in manifest["outputs"].values():
                    output_path = Path(output["path"]).resolve()
                    output_path.relative_to(salvage_root.resolve())
                    self.assertTrue(output_path.is_file())
                    self.assertEqual(hashlib.sha256(output_path.read_bytes()).hexdigest(), output["sha256"])
                self.assertEqual(summary["epoch_id"], "EPOCH-TEST-01")
                self.assertTrue(
                    (override_root / "c019_runs" / "KERNEL_GOVERNANCE_BASELINE" / expected_run_id / "crucible_coverage.json").exists()
                )
            finally:
                if previous_override is None:
                    os.environ.pop("KT_GROWTH_ARTIFACTS_ROOT", None)
                else:
                    os.environ["KT_GROWTH_ARTIFACTS_ROOT"] = previous_override


if __name__ == "__main__":
    raise SystemExit(unittest.main())
