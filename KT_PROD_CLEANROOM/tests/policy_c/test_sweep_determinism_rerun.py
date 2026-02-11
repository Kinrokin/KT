from __future__ import annotations

import json
import os
import shutil
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = ROOT / "04_PROD_TEMPLE_V2" / "src"

import sys

sys.path.insert(0, str(SRC_ROOT))
sys.path.insert(0, str(ROOT))

from core.runtime_registry import load_runtime_registry  # noqa: E402
from policy_c.dataset_export import export_dataset  # noqa: E402
from policy_c.pressure_tensor import PressureTensor  # noqa: E402
from policy_c.sweep_runner import run_sweep  # noqa: E402


def _tensor(intensity: float) -> dict:
    base = {
        "schema_id": "kt.policy_c.pressure_tensor.v1",
        "axes": {
            "time": {"intensity": intensity, "enabled": True},
            "universe": {"intensity": 0.0, "enabled": True},
            "language": {"intensity": 0.0, "enabled": True},
            "hop": {"intensity": 0.0, "enabled": True},
            "step": {"intensity": 0.0, "enabled": True},
            "paradox": {"intensity": 0.0, "enabled": True},
            "puzzle": {"intensity": 0.0, "enabled": True},
        },
        "projection": {
            "rule": "weighted_sum",
            "weights": {
                "time": 1.0,
                "universe": 1.0,
                "language": 1.0,
                "hop": 1.0,
                "step": 1.0,
                "paradox": 1.0,
                "puzzle": 1.0,
            },
            "clamp_min": 0.0,
            "clamp_max": 1.0,
        },
        "invariants": {
            "reversible": True,
            "isolated": True,
            "no_cross_axis_bleed": True,
        },
    }
    # Validate through the policy_c validator to ensure schema conformance.
    PressureTensor.from_dict(base)
    return base


def _write_plan(path: Path, export_root_rel: str) -> None:
    plan = {
        "schema_id": "kt.policy_c.sweep_plan.v1",
        "sweep_id": "determinism_sweep",
        "baseline_epoch_id": "baseline",
        "max_runs": 4,
        "seed": 0,
        "export": {"export_root": export_root_rel},
        "runs": [
            {"run_id": "baseline", "epoch_plan": {"epoch_id": "PC_BASE", "pressure_tensor": _tensor(0.0)}},
            {"run_id": "warn", "epoch_plan": {"epoch_id": "PC_WARN", "pressure_tensor": _tensor(0.08)}},
        ],
    }
    path.write_text(json.dumps(plan, indent=2), encoding="utf-8")


def _collect_hashes(out_root: Path) -> dict:
    sweep = json.loads((out_root / "policy_c_sweep_result.json").read_text(encoding="utf-8"))
    manifest = json.loads((out_root / "kt_policy_c_dataset_manifest_v1.json").read_text(encoding="utf-8"))
    return {
        "pressure_tensor_hashes": [r["hashes"]["pressure_tensor_hash"] for r in sweep["run_results"]],
        "summary_hashes": [r["hashes"]["summary_hash"] for r in sweep["run_results"]],
        "drift_report_hashes": [r["hashes"]["drift_report_hash"] for r in sweep["run_results"]],
        "records_hash": manifest["records_hash"],
        "manifest_hash": manifest["manifest_hash"],
        "sweep_content_hash": sweep["content_hash"],
    }


class TestSweepDeterminismRerun(unittest.TestCase):
    def test_rerun_content_hashes(self) -> None:
        registry = load_runtime_registry()

        if os.environ.get("KT_SEAL_MODE", "0") == "1":
            tmp = os.environ.get("TMPDIR") or os.environ.get("TMP") or os.environ.get("TEMP") or ""
            if not tmp:
                raise RuntimeError("KT_SEAL_MODE=1 requires TMPDIR/TMP/TEMP (fail-closed)")
            allowed_root = (Path(tmp).resolve() / "policy_c").resolve()
        else:
            allowed_root = ROOT / registry.policy_c.sweep.allowed_export_roots[0]
        allowed_root.mkdir(parents=True, exist_ok=True)

        out_root_a = allowed_root / "_determinism_a"
        out_root_b = allowed_root / "_determinism_b"
        plan_path = allowed_root / "_determinism_plan.json"

        try:
            export_root_a = out_root_a.resolve()
            export_root_raw = (
                export_root_a.relative_to(ROOT).as_posix() if os.environ.get("KT_SEAL_MODE", "0") != "1" else export_root_a.as_posix()
            )
            _write_plan(plan_path, export_root_raw)
            run_sweep(plan_path=plan_path, out_root=out_root_a)
            export_dataset(sweep_result_path=out_root_a / "policy_c_sweep_result.json", out_root=out_root_a)
            hashes_a = _collect_hashes(out_root_a)

            export_root_b = out_root_b.resolve()
            export_root_raw = (
                export_root_b.relative_to(ROOT).as_posix() if os.environ.get("KT_SEAL_MODE", "0") != "1" else export_root_b.as_posix()
            )
            _write_plan(plan_path, export_root_raw)
            run_sweep(plan_path=plan_path, out_root=out_root_b)
            export_dataset(sweep_result_path=out_root_b / "policy_c_sweep_result.json", out_root=out_root_b)
            hashes_b = _collect_hashes(out_root_b)

            self.assertEqual(hashes_a, hashes_b)
        finally:
            if plan_path.exists():
                plan_path.unlink()
            if out_root_a.exists():
                shutil.rmtree(out_root_a, ignore_errors=True)
            if out_root_b.exists():
                shutil.rmtree(out_root_b, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
