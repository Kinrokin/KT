from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = ROOT / "04_PROD_TEMPLE_V2" / "src"
sys.path.insert(0, str(SRC_ROOT))
sys.path.insert(0, str(ROOT))

from core.runtime_registry import load_runtime_registry  # noqa: E402
from policy_c.dataset_export import export_dataset  # noqa: E402


class TestDatasetExportDeterminism(unittest.TestCase):
    def test_deterministic_export(self) -> None:
        registry = load_runtime_registry()
        allowed_root = ROOT / registry.policy_c.sweep.allowed_export_roots[0]
        allowed_root.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory(dir=str(allowed_root)) as td:
            temp_root = Path(td)
            sweep_result_path = temp_root / "policy_c_sweep_result.json"

            run_dir = temp_root / "runs" / "r1"
            run_dir.mkdir(parents=True, exist_ok=True)
            pressure_path = run_dir / "pressure_tensor.json"
            epoch_summary_path = run_dir / "policy_c_epoch_summary.json"
            drift_path = run_dir / "policy_c_drift_report.json"

            pressure_path.write_text(json.dumps({"schema_id": "kt.policy_c.pressure_tensor.v1"}), encoding="utf-8")
            epoch_summary_path.write_text(json.dumps({"timestamp_utc": "T"}), encoding="utf-8")
            drift_path.write_text(json.dumps({"schema_id": "kt.policy_c.drift_report.v1"}), encoding="utf-8")

            sweep = {
                "schema_id": "kt.policy_c.sweep_result.v1",
                "sweep_id": "s1",
                "started_at": "T0",
                "finished_at": "T1",
                "runs_total": 1,
                "runs_pass": 1,
                "runs_warn": 0,
                "runs_fail": 0,
                "run_results": [
                    {
                        "run_id": "r1",
                        "epoch_id": "e1",
                        "status": "PASS",
                        "reason_codes": [],
                        "paths": {
                            "pressure_tensor": pressure_path.as_posix(),
                            "epoch_summary": epoch_summary_path.as_posix(),
                            "drift_report": drift_path.as_posix(),
                        },
                        "hashes": {
                            "pressure_tensor_hash": "a" * 64,
                            "summary_hash": "b" * 64,
                            "drift_report_hash": "c" * 64,
                        },
                    }
                ],
            }
            sweep_result_path.write_text(json.dumps(sweep, indent=2), encoding="utf-8")

            out_root = temp_root / "export"
            manifest_a = export_dataset(sweep_result_path=sweep_result_path, out_root=out_root)
            manifest_b = export_dataset(sweep_result_path=sweep_result_path, out_root=out_root)

            self.assertEqual(manifest_a["records_hash"], manifest_b["records_hash"])
            self.assertEqual(manifest_a["manifest_hash"], manifest_b["manifest_hash"])


if __name__ == "__main__":
    raise SystemExit(unittest.main())
