from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path


def _add_plus_to_syspath() -> None:
    # .../tools/growth/eval_harness_plus/tests/test_eval_harness_plus.py -> .../tools/growth/eval_harness_plus
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))


_add_plus_to_syspath()

from eval_plus_runner import _require_json_object, main as eval_plus_main  # noqa: E402
from eval_plus_schemas import (  # noqa: E402
    DriftMetricVectorSchema,
    ExtendedBenchmarkResultSchema,
    GoldenZoneSchema,
    ParadoxMetricVectorSchema,
    compute_paradox_vector,
)


class TestEvalHarnessPlus(unittest.TestCase):
    def test_deterministic_vector_hash(self) -> None:
        v1 = compute_paradox_vector(
            outcomes={"PASS": 3, "FAIL": 1},
            replay_verified=3,
            replay_total=4,
            governance_types={"GOV_POLICY_APPLY": 4},
        )
        v2 = compute_paradox_vector(
            outcomes={"PASS": 3, "FAIL": 1},
            replay_verified=3,
            replay_total=4,
            governance_types={"GOV_POLICY_APPLY": 4},
        )
        self.assertEqual(v1.vector_hash, v2.vector_hash)

    def test_bounds_enforced(self) -> None:
        with self.assertRaises(ValueError):
            ParadoxMetricVectorSchema.from_parts(
                axes={"pass_rate": 1.1, "refusal_ratio": 0.0, "replay_consistency": 0.0, "governance_entropy": 0.0},
                support={"total": 1},
            )

    def test_golden_zone_gate(self) -> None:
        golden = GoldenZoneSchema.evaluate(metric="replay_consistency", score=0.5, min_val=0.6, max_val=0.9)
        self.assertEqual(golden.verdict, "UNDER_RANGE")

        golden2 = GoldenZoneSchema.evaluate(metric="replay_consistency", score=0.7, min_val=0.6, max_val=0.9)
        self.assertEqual(golden2.verdict, "WITHIN_RANGE")

    def test_extended_result_hash_and_status(self) -> None:
        paradox = compute_paradox_vector(
            outcomes={"PASS": 1},
            replay_verified=1,
            replay_total=1,
            governance_types={"GOV_POLICY_APPLY": 1},
        )
        golden = GoldenZoneSchema.evaluate(metric="replay_consistency", score=paradox.axes["replay_consistency"], min_val=0.0, max_val=1.0)
        res = ExtendedBenchmarkResultSchema.from_parts(
            epoch_id="EPOCH-TEST",
            kernel_identity={"kernel_target": "V2_SOVEREIGN", "kernel_build_id": "unknown"},
            paradox=paradox,
            drift=None,
            golden_zone=golden,
        )
        self.assertEqual(res.status, "PASS")
        self.assertEqual(len(res.result_hash), 64)


class TestExternalEpochInput(unittest.TestCase):
    def _write_epoch_fixture(
        self, root: Path, *, epoch_name: str, run_record: dict
    ) -> tuple[Path, Path, Path]:
        growth_root = root / "growth"
        epoch_dir = growth_root / "epochs" / epoch_name
        record_path = epoch_dir / "CRU-TEST" / "run_record.json"
        record_path.parent.mkdir(parents=True)
        record_path.write_text(json.dumps(run_record), encoding="utf-8")
        (epoch_dir / "epoch_manifest.json").write_text(
            json.dumps(
                {"kernel_identity": {"kernel_target": "V2_SOVEREIGN", "kernel_build_id": "fixture"}}
            ),
            encoding="utf-8",
        )
        run_id = run_record.get("run_id")
        if isinstance(run_id, str) and len(run_id) == 64:
            run_dir = growth_root / "c019_runs" / "V2_SOVEREIGN" / run_id
            run_dir.mkdir(parents=True)
            (run_dir / "replay_report.json").write_text('{"status":"PASS"}', encoding="utf-8")
        return growth_root, epoch_dir, root / "must-not-exist.json"

    def test_external_epoch_preserves_metrics_and_write_once_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root = root / "external growth"
            epoch_dir = growth_root / "epochs" / "EPOCH-EXTERNAL_RUN1"
            record_path = epoch_dir / "CRU-TEST" / "run_record.json"
            record_path.parent.mkdir(parents=True)
            run_id = "a" * 64
            record_path.write_text(json.dumps({"run_id": run_id, "outcome": "PASS"}), encoding="utf-8")
            (epoch_dir / "epoch_manifest.json").write_text(
                json.dumps({"kernel_identity": {"kernel_target": "V2_SOVEREIGN", "kernel_build_id": "fixture"}}),
                encoding="utf-8",
            )
            run_dir = growth_root / "c019_runs" / "V2_SOVEREIGN" / run_id
            run_dir.mkdir(parents=True)
            (run_dir / "replay_report.json").write_text('{"status":"PASS"}', encoding="utf-8")
            (run_dir / "governance_report.json").write_text('{"types":["FIXTURE"]}', encoding="utf-8")
            out = root / "results" / "eval.json"
            argv = ["eval_plus_runner", "--epoch-dir", str(epoch_dir), "--epoch-id", epoch_dir.name, "--out", str(out)]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}):
                with patch.object(sys, "argv", argv):
                    self.assertEqual(eval_plus_main(), 0)
                before = out.read_bytes()
                result = json.loads(before)
                self.assertEqual(result["paradox"]["axes"]["pass_rate"], 1.0)
                self.assertEqual(result["paradox"]["axes"]["replay_consistency"], 1.0)
                with patch.object(sys, "argv", argv):
                    with self.assertRaisesRegex(SystemExit, "refuse_overwrite"):
                        eval_plus_main()
                with patch.object(sys, "argv", argv + ["--allow-existing"]):
                    self.assertEqual(eval_plus_main(), 0)
                self.assertEqual(out.read_bytes(), before)
                record_path.write_text(json.dumps({"run_id": run_id, "outcome": "FAIL"}), encoding="utf-8")
                with patch.object(sys, "argv", argv + ["--allow-existing"]):
                    with self.assertRaisesRegex(SystemExit, "existing_output_hash_mismatch"):
                        eval_plus_main()
                self.assertEqual(out.read_bytes(), before)

    def test_external_epoch_escape_is_rejected_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root = root / "growth"
            outside = growth_root / "epochs" / ".." / ".." / "outside"
            outside.resolve().mkdir(parents=True)
            out = root / "must-not-exist.json"
            argv = ["eval_plus_runner", "--epoch-dir", str(outside), "--epoch-id", "EPOCH-OUTSIDE", "--out", str(out)]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "epoch_dir_parent_component_forbidden"):
                    eval_plus_main()
            self.assertFalse(out.exists())

    def test_missing_run_outcome_is_rejected_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root, epoch_dir, out = self._write_epoch_fixture(
                root, epoch_name="EPOCH-MISSING-OUTCOME", run_record={"run_id": "a" * 64}
            )
            argv = ["eval_plus_runner", "--epoch-dir", str(epoch_dir), "--epoch-id", epoch_dir.name, "--out", str(out)]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "invalid_or_missing_run_outcome"):
                    eval_plus_main()
            self.assertFalse(out.exists())

    def test_non_string_run_outcome_is_rejected_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root, epoch_dir, out = self._write_epoch_fixture(
                root, epoch_name="EPOCH-NONSTRING-OUTCOME", run_record={"run_id": "a" * 64, "outcome": 1}
            )
            argv = ["eval_plus_runner", "--epoch-dir", str(epoch_dir), "--epoch-id", epoch_dir.name, "--out", str(out)]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "invalid_or_missing_run_outcome"):
                    eval_plus_main()
            self.assertFalse(out.exists())

    def test_unknown_run_outcome_is_rejected_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root, epoch_dir, out = self._write_epoch_fixture(
                root, epoch_name="EPOCH-UNKNOWN-OUTCOME", run_record={"run_id": "a" * 64, "outcome": "TIMEOUT"}
            )
            argv = ["eval_plus_runner", "--epoch-dir", str(epoch_dir), "--epoch-id", epoch_dir.name, "--out", str(out)]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "invalid_or_missing_run_outcome"):
                    eval_plus_main()
            self.assertFalse(out.exists())

    def test_epoch_id_must_match_validated_directory_name(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root, epoch_dir, out = self._write_epoch_fixture(
                root, epoch_name="EPOCH-A", run_record={"run_id": "a" * 64, "outcome": "PASS"}
            )
            argv = ["eval_plus_runner", "--epoch-dir", str(epoch_dir), "--epoch-id", "EPOCH-B", "--out", str(out)]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "epoch_id_directory_mismatch"):
                    eval_plus_main()
            self.assertFalse(out.exists())

    def test_unsafe_epoch_id_label_is_rejected_before_input_read(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root, epoch_dir, out = self._write_epoch_fixture(
                root, epoch_name="EPOCH-SAFE", run_record={"run_id": "a" * 64, "outcome": "PASS"}
            )
            argv = ["eval_plus_runner", "--epoch-dir", str(epoch_dir), "--epoch-id", "../EPOCH-SAFE", "--out", str(out)]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "invalid_epoch_id_label"):
                    eval_plus_main()
            self.assertFalse(out.exists())

    def test_json_reader_rejects_path_swap_after_descriptor_open(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "evidence.json"
            outside = root.parent / f"{root.name}-outside.json"
            target.write_text('{"source":"inside"}', encoding="utf-8")
            outside.write_text('{"source":"outside"}', encoding="utf-8")
            real_open = os.open
            swapped = False

            def open_then_swap(path, flags, *args, **kwargs):
                nonlocal swapped
                descriptor = real_open(path, flags, *args, **kwargs)
                if Path(path) == target and not swapped:
                    target.unlink()
                    try:
                        target.symlink_to(outside)
                    except OSError as exc:
                        os.close(descriptor)
                        raise unittest.SkipTest(f"symlink unavailable: {exc}")
                    swapped = True
                return descriptor

            try:
                with patch("eval_plus_runner.os.open", side_effect=open_then_swap):
                    with self.assertRaisesRegex(ValueError, "link_or_reparse_forbidden|path_changed_during_open"):
                        _require_json_object(target, root=root, label="race_input")
            finally:
                outside.unlink(missing_ok=True)

    def test_parent_component_is_rejected_before_link_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root = root / "growth"
            growth_root.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (growth_root / "linked").symlink_to(outside, target_is_directory=True)
            epoch_argument = growth_root / "linked" / ".." / "epochs" / "EPOCH-PARENT-RUN1"
            out = root / "must-not-exist.json"
            argv = [
                "eval_plus_runner", "--epoch-dir", str(epoch_argument),
                "--epoch-id", "EPOCH-PARENT-RUN1", "--out", str(out),
            ]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "epoch_dir_parent_component_forbidden"):
                    eval_plus_main()
            self.assertFalse(out.exists())

    def test_trailing_dot_epoch_component_is_rejected_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root = root / "growth"
            epoch_argument = growth_root / "epochs" / "EPOCH-ALIAS-RUN1."
            out = root / "must-not-exist.json"
            argv = [
                "eval_plus_runner", "--epoch-dir", str(epoch_argument),
                "--epoch-id", "EPOCH-ALIAS-RUN1", "--out", str(out),
            ]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "epoch_dir_nonportable_path_component"):
                    eval_plus_main()
            self.assertFalse(out.exists())

    def test_trailing_space_epoch_component_is_rejected_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root = root / "growth"
            epoch_argument = growth_root / "epochs" / "EPOCH-ALIAS-RUN1 "
            out = root / "must-not-exist.json"
            argv = [
                "eval_plus_runner", "--epoch-dir", str(epoch_argument),
                "--epoch-id", "EPOCH-ALIAS-RUN1", "--out", str(out),
            ]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "epoch_dir_nonportable_path_component"):
                    eval_plus_main()
            self.assertFalse(out.exists())

    def test_concurrent_output_creation_has_one_writer(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root = root / "growth"
            epoch_dir = growth_root / "epochs" / "EPOCH-CONCURRENT-RUN1"
            run_id = "a" * 64
            epoch_dir.mkdir(parents=True)
            (epoch_dir / "epoch_manifest.json").write_text(
                json.dumps({"kernel_identity": {"kernel_target": "V2_SOVEREIGN", "kernel_build_id": "fixture"}}),
                encoding="utf-8",
            )
            (epoch_dir / "run_record.json").write_text(
                json.dumps({"run_id": run_id, "outcome": "PASS"}), encoding="utf-8"
            )
            c019_dir = growth_root / "c019_runs" / "V2_SOVEREIGN" / run_id
            c019_dir.mkdir(parents=True)
            (c019_dir / "replay_report.json").write_text('{"status":"PASS"}', encoding="utf-8")
            out = root / "results" / "eval.json"
            runner = Path(__file__).resolve().parents[1] / "eval_plus_runner.py"
            command = [
                sys.executable, str(runner), "--epoch-dir", str(epoch_dir),
                "--epoch-id", epoch_dir.name, "--out", str(out),
            ]
            env = dict(os.environ)
            env["KT_GROWTH_ARTIFACTS_ROOT"] = str(growth_root)
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            processes = [
                subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
                for _ in range(2)
            ]
            results = [(process.returncode, stdout, stderr) for process in processes for stdout, stderr in [process.communicate(timeout=30)]]
            self.assertEqual(sorted(code for code, _, _ in results), [0, 1])
            loser = next(stderr for code, _, stderr in results if code != 0)
            self.assertIn("refuse_overwrite", loser)
            ExtendedBenchmarkResultSchema.validate(json.loads(out.read_text(encoding="utf-8")))

    def test_missing_or_empty_epoch_is_rejected_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root = root / "growth"
            epoch_dir = growth_root / "epochs" / "EPOCH-EMPTY_RUN1"
            out = root / "must-not-exist.json"
            argv = ["eval_plus_runner", "--epoch-dir", str(epoch_dir), "--epoch-id", epoch_dir.name, "--out", str(out)]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}):
                with patch.object(sys, "argv", argv):
                    with self.assertRaisesRegex(ValueError, "epoch_dir_missing_or_not_directory"):
                        eval_plus_main()
                epoch_dir.mkdir(parents=True)
                with patch.object(sys, "argv", argv):
                    with self.assertRaisesRegex(ValueError, "epoch_manifest_missing"):
                        eval_plus_main()
                (epoch_dir / "epoch_manifest.json").write_text(
                    json.dumps({"kernel_identity": {"kernel_target": "V2_SOVEREIGN", "kernel_build_id": "fixture"}}), encoding="utf-8"
                )
                with patch.object(sys, "argv", argv):
                    with self.assertRaisesRegex(ValueError, "epoch_run_records_missing"):
                        eval_plus_main()
            self.assertFalse(out.exists())

    def test_nested_epoch_directory_is_rejected_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root = root / "growth"
            epoch_dir = growth_root / "epochs" / "nested" / "EPOCH-NESTED_RUN1"
            epoch_dir.mkdir(parents=True)
            out = root / "must-not-exist.json"
            argv = ["eval_plus_runner", "--epoch-dir", str(epoch_dir), "--epoch-id", epoch_dir.name, "--out", str(out)]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "epoch_dir_not_direct_child"):
                    eval_plus_main()
            self.assertFalse(out.exists())

    def test_missing_run_id_is_rejected_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root = root / "growth"
            epoch_dir = growth_root / "epochs" / "EPOCH-MISSING_ID_RUN1"
            record_path = epoch_dir / "CRU-TEST" / "run_record.json"
            record_path.parent.mkdir(parents=True)
            record_path.write_text(json.dumps({"outcome": "PASS"}), encoding="utf-8")
            (epoch_dir / "epoch_manifest.json").write_text(
                json.dumps({"kernel_identity": {"kernel_target": "V2_SOVEREIGN", "kernel_build_id": "fixture"}}), encoding="utf-8"
            )
            out = root / "must-not-exist.json"
            argv = ["eval_plus_runner", "--epoch-dir", str(epoch_dir), "--epoch-id", epoch_dir.name, "--out", str(out)]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "invalid_or_missing_run_id_path_component"):
                    eval_plus_main()
            self.assertFalse(out.exists())

    def test_missing_replay_report_is_rejected_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root = root / "growth"
            epoch_dir = growth_root / "epochs" / "EPOCH-MISSING_REPLAY_RUN1"
            run_id = "a" * 64
            record_path = epoch_dir / "CRU-TEST" / "run_record.json"
            record_path.parent.mkdir(parents=True)
            record_path.write_text(json.dumps({"run_id": run_id, "outcome": "PASS"}), encoding="utf-8")
            (epoch_dir / "epoch_manifest.json").write_text(
                json.dumps({"kernel_identity": {"kernel_target": "V2_SOVEREIGN", "kernel_build_id": "fixture"}}), encoding="utf-8"
            )
            (growth_root / "c019_runs" / "V2_SOVEREIGN" / run_id).mkdir(parents=True)
            out = root / "must-not-exist.json"
            argv = ["eval_plus_runner", "--epoch-dir", str(epoch_dir), "--epoch-id", epoch_dir.name, "--out", str(out)]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "replay_report_missing"):
                    eval_plus_main()
            self.assertFalse(out.exists())

    def test_symlinked_manifest_is_rejected_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root = root / "growth"
            epoch_dir = growth_root / "epochs" / "EPOCH-LINKED_MANIFEST_RUN1"
            epoch_dir.mkdir(parents=True)
            outside = root / "outside-manifest.json"
            outside.write_text(
                json.dumps({"kernel_identity": {"kernel_target": "V2_SOVEREIGN", "kernel_build_id": "fixture"}}),
                encoding="utf-8",
            )
            (epoch_dir / "epoch_manifest.json").symlink_to(outside)
            (epoch_dir / "run_record.json").write_text(
                json.dumps({"run_id": "a" * 64, "outcome": "PASS"}), encoding="utf-8"
            )
            out = root / "must-not-exist.json"
            argv = ["eval_plus_runner", "--epoch-dir", str(epoch_dir), "--epoch-id", epoch_dir.name, "--out", str(out)]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "epoch_manifest_link_or_reparse_forbidden"):
                    eval_plus_main()
            self.assertFalse(out.exists())

    def test_symlinked_run_record_is_rejected_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root = root / "growth"
            epoch_dir = growth_root / "epochs" / "EPOCH-LINKED_RECORD_RUN1"
            epoch_dir.mkdir(parents=True)
            (epoch_dir / "epoch_manifest.json").write_text(
                json.dumps({"kernel_identity": {"kernel_target": "V2_SOVEREIGN", "kernel_build_id": "fixture"}}), encoding="utf-8"
            )
            outside = root / "outside-record.json"
            outside.write_text(json.dumps({"run_id": "a" * 64, "outcome": "PASS"}), encoding="utf-8")
            (epoch_dir / "run_record.json").symlink_to(outside)
            out = root / "must-not-exist.json"
            argv = ["eval_plus_runner", "--epoch-dir", str(epoch_dir), "--epoch-id", epoch_dir.name, "--out", str(out)]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "run_record_link_or_reparse_forbidden"):
                    eval_plus_main()
            self.assertFalse(out.exists())

    def test_symlinked_replay_report_is_rejected_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root = root / "growth"
            epoch_dir = growth_root / "epochs" / "EPOCH-LINKED_REPLAY_RUN1"
            run_id = "a" * 64
            epoch_dir.mkdir(parents=True)
            (epoch_dir / "epoch_manifest.json").write_text(
                json.dumps({"kernel_identity": {"kernel_target": "V2_SOVEREIGN", "kernel_build_id": "fixture"}}), encoding="utf-8"
            )
            (epoch_dir / "run_record.json").write_text(
                json.dumps({"run_id": run_id, "outcome": "PASS"}), encoding="utf-8"
            )
            c019_dir = growth_root / "c019_runs" / "V2_SOVEREIGN" / run_id
            c019_dir.mkdir(parents=True)
            outside = root / "outside-replay.json"
            outside.write_text('{"status":"PASS"}', encoding="utf-8")
            (c019_dir / "replay_report.json").symlink_to(outside)
            out = root / "must-not-exist.json"
            argv = ["eval_plus_runner", "--epoch-dir", str(epoch_dir), "--epoch-id", epoch_dir.name, "--out", str(out)]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "replay_report_link_or_reparse_forbidden"):
                    eval_plus_main()
            self.assertFalse(out.exists())

    def test_symlinked_governance_report_is_rejected_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root = root / "growth"
            epoch_dir = growth_root / "epochs" / "EPOCH-LINKED-GOVERNANCE-RUN1"
            run_id = "a" * 64
            epoch_dir.mkdir(parents=True)
            (epoch_dir / "epoch_manifest.json").write_text(
                json.dumps({"kernel_identity": {"kernel_target": "V2_SOVEREIGN", "kernel_build_id": "fixture"}}), encoding="utf-8"
            )
            (epoch_dir / "run_record.json").write_text(
                json.dumps({"run_id": run_id, "outcome": "PASS"}), encoding="utf-8"
            )
            c019_dir = growth_root / "c019_runs" / "V2_SOVEREIGN" / run_id
            c019_dir.mkdir(parents=True)
            (c019_dir / "replay_report.json").write_text('{"status":"PASS"}', encoding="utf-8")
            outside = root / "outside-governance.json"
            outside.write_text('{"types":[]}', encoding="utf-8")
            (c019_dir / "governance_report.json").symlink_to(outside)
            out = root / "must-not-exist.json"
            argv = ["eval_plus_runner", "--epoch-dir", str(epoch_dir), "--epoch-id", epoch_dir.name, "--out", str(out)]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "governance_report_link_or_reparse_forbidden"):
                    eval_plus_main()
            self.assertFalse(out.exists())

    def test_dangling_governance_report_symlink_is_rejected_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root = root / "growth"
            epoch_dir = growth_root / "epochs" / "EPOCH-DANGLING-GOVERNANCE-RUN1"
            run_id = "a" * 64
            epoch_dir.mkdir(parents=True)
            (epoch_dir / "epoch_manifest.json").write_text(
                json.dumps({"kernel_identity": {"kernel_target": "V2_SOVEREIGN", "kernel_build_id": "fixture"}}), encoding="utf-8"
            )
            (epoch_dir / "run_record.json").write_text(
                json.dumps({"run_id": run_id, "outcome": "PASS"}), encoding="utf-8"
            )
            c019_dir = growth_root / "c019_runs" / "V2_SOVEREIGN" / run_id
            c019_dir.mkdir(parents=True)
            (c019_dir / "replay_report.json").write_text('{"status":"PASS"}', encoding="utf-8")
            (c019_dir / "governance_report.json").symlink_to(root / "missing-governance.json")
            out = root / "must-not-exist.json"
            argv = ["eval_plus_runner", "--epoch-dir", str(epoch_dir), "--epoch-id", epoch_dir.name, "--out", str(out)]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "governance_report_link_or_reparse_forbidden"):
                    eval_plus_main()
            self.assertFalse(out.exists())

    def test_symlinked_epochs_root_is_rejected_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root = root / "growth"
            growth_root.mkdir()
            outside_epochs = root / "outside-epochs"
            epoch_dir = outside_epochs / "EPOCH-LINKED-EPOCHS-RUN1"
            epoch_dir.mkdir(parents=True)
            (growth_root / "epochs").symlink_to(outside_epochs, target_is_directory=True)
            out = root / "must-not-exist.json"
            linked_epoch = growth_root / "epochs" / epoch_dir.name
            argv = ["eval_plus_runner", "--epoch-dir", str(linked_epoch), "--epoch-id", linked_epoch.name, "--out", str(out)]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "epochs_root_link_or_reparse_forbidden"):
                    eval_plus_main()
            self.assertFalse(out.exists())

    def test_symlinked_c019_root_is_rejected_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root = root / "growth"
            epoch_dir = growth_root / "epochs" / "EPOCH-LINKED-C019-RUN1"
            run_id = "a" * 64
            epoch_dir.mkdir(parents=True)
            (epoch_dir / "epoch_manifest.json").write_text(
                json.dumps({"kernel_identity": {"kernel_target": "V2_SOVEREIGN", "kernel_build_id": "fixture"}}), encoding="utf-8"
            )
            (epoch_dir / "run_record.json").write_text(
                json.dumps({"run_id": run_id, "outcome": "PASS"}), encoding="utf-8"
            )
            outside_c019 = root / "outside-c019"
            outside_c019.mkdir()
            (growth_root / "c019_runs").symlink_to(outside_c019, target_is_directory=True)
            out = root / "must-not-exist.json"
            argv = ["eval_plus_runner", "--epoch-dir", str(epoch_dir), "--epoch-id", epoch_dir.name, "--out", str(out)]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "c019_root_link_or_reparse_forbidden"):
                    eval_plus_main()
            self.assertFalse(out.exists())

    def _assert_duplicate_json_key_rejected(self, source: str) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root = root / "growth"
            epoch_dir = growth_root / "epochs" / "EPOCH-DUPLICATE-JSON-RUN1"
            run_id = "a" * 64
            epoch_dir.mkdir(parents=True)
            manifest = '{"kernel_identity":{"kernel_target":"V2_SOVEREIGN","kernel_build_id":"fixture"}}'
            record = f'{{"run_id":"{run_id}","outcome":"PASS"}}'
            replay = '{"status":"PASS"}'
            if source == "manifest":
                manifest = '{"kernel_identity":{"kernel_target":"V2_SOVEREIGN","kernel_target":"OTHER","kernel_build_id":"fixture"}}'
            elif source == "run_record":
                duplicate_id = "b" * 64
                record = f'{{"run_id":"{run_id}","run_id":"{duplicate_id}","outcome":"PASS"}}'
            elif source == "replay_report":
                replay = '{"status":"FAIL","status":"PASS"}'
            else:
                raise AssertionError(f"unexpected source: {source}")
            (epoch_dir / "epoch_manifest.json").write_text(manifest, encoding="utf-8")
            (epoch_dir / "run_record.json").write_text(record, encoding="utf-8")
            c019_dir = growth_root / "c019_runs" / "V2_SOVEREIGN" / run_id
            c019_dir.mkdir(parents=True)
            (c019_dir / "replay_report.json").write_text(replay, encoding="utf-8")
            out = root / "must-not-exist.json"
            argv = ["eval_plus_runner", "--epoch-dir", str(epoch_dir), "--epoch-id", epoch_dir.name, "--out", str(out)]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "duplicate_json_key"):
                    eval_plus_main()
            self.assertFalse(out.exists())

    def test_duplicate_manifest_key_is_rejected_before_output(self) -> None:
        self._assert_duplicate_json_key_rejected("manifest")

    def test_duplicate_run_record_key_is_rejected_before_output(self) -> None:
        self._assert_duplicate_json_key_rejected("run_record")

    def test_duplicate_replay_report_key_is_rejected_before_output(self) -> None:
        self._assert_duplicate_json_key_rejected("replay_report")

    def _assert_invalid_kernel_identity_rejected(self, identity: object) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root = root / "growth"
            epoch_dir = growth_root / "epochs" / "EPOCH-BAD-IDENTITY-RUN1"
            epoch_dir.mkdir(parents=True)
            (epoch_dir / "epoch_manifest.json").write_text(
                json.dumps({"kernel_identity": identity}), encoding="utf-8"
            )
            (epoch_dir / "run_record.json").write_text(
                json.dumps({"run_id": "a" * 64, "outcome": "PASS"}), encoding="utf-8"
            )
            out = root / "must-not-exist.json"
            argv = ["eval_plus_runner", "--epoch-dir", str(epoch_dir), "--epoch-id", epoch_dir.name, "--out", str(out)]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "invalid_or_missing_kernel_identity_fields"):
                    eval_plus_main()
            self.assertFalse(out.exists())

    def test_non_string_kernel_target_is_rejected_before_output(self) -> None:
        self._assert_invalid_kernel_identity_rejected(
            {"kernel_target": 123, "kernel_build_id": "fixture"}
        )

    def test_non_string_kernel_build_id_is_rejected_before_output(self) -> None:
        self._assert_invalid_kernel_identity_rejected(
            {"kernel_target": "V2_SOVEREIGN", "kernel_build_id": None}
        )

    def test_dangling_output_symlink_is_rejected_before_input_read(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root = root / "growth"
            epoch_dir = growth_root / "epochs" / "EPOCH-OUTPUT-LINK-RUN1"
            out = root / "linked-output.json"
            target = root / "outside" / "created-through-link.json"
            try:
                out.symlink_to(target)
            except OSError as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            argv = ["eval_plus_runner", "--epoch-dir", str(epoch_dir), "--epoch-id", epoch_dir.name, "--out", str(out)]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, "output_link_or_reparse_forbidden"):
                    eval_plus_main()
            self.assertTrue(out.is_symlink())
            self.assertFalse(target.exists())

    def _assert_untrusted_c019_path_component_rejected(
        self, *, kernel_target: str, run_id: str, expected: str
    ) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            growth_root = root / "growth"
            epoch_dir = growth_root / "epochs" / "EPOCH-UNTRUSTED_RUN1"
            record_path = epoch_dir / "CRU-TEST" / "run_record.json"
            record_path.parent.mkdir(parents=True)
            record_path.write_text(json.dumps({"run_id": run_id, "outcome": "PASS"}), encoding="utf-8")
            (epoch_dir / "epoch_manifest.json").write_text(
                json.dumps({"kernel_identity": {"kernel_target": kernel_target, "kernel_build_id": "fixture"}}),
                encoding="utf-8",
            )
            out = root / "must-not-exist.json"
            argv = ["eval_plus_runner", "--epoch-dir", str(epoch_dir), "--epoch-id", epoch_dir.name, "--out", str(out)]
            with patch.dict(os.environ, {"KT_GROWTH_ARTIFACTS_ROOT": str(growth_root)}), patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(ValueError, expected):
                    eval_plus_main()
            self.assertFalse(out.exists())

    def test_untrusted_kernel_target_is_rejected_before_output(self) -> None:
        self._assert_untrusted_c019_path_component_rejected(
            kernel_target="../outside",
            run_id="a" * 64,
            expected="invalid_kernel_target_path_component",
        )

    def test_trailing_dot_kernel_target_is_rejected_before_output(self) -> None:
        self._assert_untrusted_c019_path_component_rejected(
            kernel_target="V2_SOVEREIGN.",
            run_id="a" * 64,
            expected="invalid_kernel_target_path_component",
        )

    def test_trailing_space_kernel_target_is_rejected_before_output(self) -> None:
        self._assert_untrusted_c019_path_component_rejected(
            kernel_target="V2_SOVEREIGN ",
            run_id="a" * 64,
            expected="invalid_kernel_target_path_component",
        )

    def test_untrusted_run_id_is_rejected_before_output(self) -> None:
        self._assert_untrusted_c019_path_component_rejected(
            kernel_target="V2_SOVEREIGN",
            run_id="../" * 20 + "evil",
            expected="invalid_or_missing_run_id_path_component",
        )


if __name__ == "__main__":
    raise SystemExit(unittest.main())
