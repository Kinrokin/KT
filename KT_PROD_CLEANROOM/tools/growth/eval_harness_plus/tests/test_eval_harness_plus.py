from __future__ import annotations

import json
import os
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

from eval_plus_runner import main as eval_plus_main  # noqa: E402
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
                with self.assertRaisesRegex(ValueError, "epoch_dir_not_under_root"):
                    eval_plus_main()
            self.assertFalse(out.exists())

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
                    json.dumps({"kernel_identity": {"kernel_target": "V2_SOVEREIGN"}}), encoding="utf-8"
                )
                with patch.object(sys, "argv", argv):
                    with self.assertRaisesRegex(ValueError, "epoch_run_records_missing"):
                        eval_plus_main()
            self.assertFalse(out.exists())

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
                json.dumps({"kernel_identity": {"kernel_target": kernel_target}}), encoding="utf-8"
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

    def test_untrusted_run_id_is_rejected_before_output(self) -> None:
        self._assert_untrusted_c019_path_component_rejected(
            kernel_target="V2_SOVEREIGN",
            run_id="../" * 20 + "evil",
            expected="invalid_run_id_path_component",
        )


if __name__ == "__main__":
    raise SystemExit(unittest.main())
