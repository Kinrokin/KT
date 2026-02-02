from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = ROOT / "04_PROD_TEMPLE_V2" / "src"
sys.path.insert(0, str(SRC_ROOT))
sys.path.insert(0, str(ROOT))

from core.runtime_registry import load_runtime_registry  # noqa: E402
from policy_c.sweep_runner import run_sweep  # noqa: E402


def _pressure_tensor(intensity: float) -> dict:
    axes = {
        "time": {"intensity": intensity, "enabled": True},
        "universe": {"intensity": 0.0, "enabled": True},
        "language": {"intensity": 0.0, "enabled": True},
        "hop": {"intensity": 0.0, "enabled": True},
        "step": {"intensity": 0.0, "enabled": True},
        "paradox": {"intensity": 0.0, "enabled": True},
        "puzzle": {"intensity": 0.0, "enabled": True},
    }
    projection = {
        "rule": "sum",
        "weights": {
            "time": 0.0,
            "universe": 0.0,
            "language": 0.0,
            "hop": 0.0,
            "step": 0.0,
            "paradox": 0.0,
            "puzzle": 0.0,
        },
        "clamp_min": 0.0,
        "clamp_max": 1.0,
    }
    return {
        "schema_id": "kt.policy_c.pressure_tensor.v1",
        "axes": axes,
        "projection": projection,
        "invariants": {"reversible": True, "isolated": True, "no_cross_axis_bleed": True},
    }


class TestSweepRunnerIntegration(unittest.TestCase):
    def test_sweep_runner_outputs(self) -> None:
        registry = load_runtime_registry()

        if os.environ.get("KT_SEAL_MODE", "0") == "1":
            tmp = os.environ.get("TMPDIR") or os.environ.get("TMP") or os.environ.get("TEMP") or ""
            if not tmp:
                raise RuntimeError("KT_SEAL_MODE=1 requires TMPDIR/TMP/TEMP (fail-closed)")
            allowed_root = (Path(tmp).resolve() / "policy_c").resolve()
        else:
            allowed_root = ROOT / registry.policy_c.sweep.allowed_export_roots[0]
        allowed_root.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory(dir=str(allowed_root)) as td:
            temp_root = Path(td)
            plan_path = temp_root / "sweep_plan.json"
            out_root = temp_root / "outputs"

            plan = {
                "schema_id": "kt.policy_c.sweep_plan.v1",
                "sweep_id": "sweep_integration",
                "baseline_epoch_id": "run_base",
                "max_runs": 4,
                "seed": 0,
                "export": {"export_root": out_root.as_posix()},
                "runs": [
                    {
                        "run_id": "run_base",
                        "epoch_plan": {
                            "epoch_id": "epoch_base",
                            "pressure_tensor": _pressure_tensor(0.0),
                        },
                    },
                    {
                        "run_id": "run_warn",
                        "epoch_plan": {
                            "epoch_id": "epoch_warn",
                            "pressure_tensor": _pressure_tensor(0.06),
                        },
                    },
                ],
            }
            plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")

            result = run_sweep(plan_path=plan_path, out_root=out_root)
            self.assertEqual(result["runs_total"], 2)
            self.assertTrue((out_root / "policy_c_sweep_result.json").exists())


if __name__ == "__main__":
    raise SystemExit(unittest.main())
