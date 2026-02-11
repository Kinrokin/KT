from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = ROOT / "04_PROD_TEMPLE_V2" / "src"
sys.path.insert(0, str(SRC_ROOT))
sys.path.insert(0, str(ROOT))

from core.runtime_registry import PolicyCDriftSpec  # noqa: E402
from policy_c.drift_guard import evaluate_drift  # noqa: E402
from policy_c.pressure_tensor import PressureTensor, SCHEMA_ID  # noqa: E402


def _tensor_with_time(intensity: float) -> PressureTensor:
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
    invariants = {"reversible": True, "isolated": True, "no_cross_axis_bleed": True}
    payload = {"schema_id": SCHEMA_ID, "axes": axes, "projection": projection, "invariants": invariants}
    return PressureTensor.from_dict(payload)


class TestDriftGuard(unittest.TestCase):
    def setUp(self) -> None:
        self.thresholds = PolicyCDriftSpec(l2_warn=0.05, l2_fail=0.10, max_fail=0.10)

    def test_zero_drift_pass(self) -> None:
        base = _tensor_with_time(0.0)
        curr = _tensor_with_time(0.0)
        report = evaluate_drift(
            epoch_id="E1",
            baseline_epoch_id="B0",
            baseline_tensor=base,
            current_tensor=curr,
            invariant_violations=0,
            thresholds=self.thresholds,
        )
        self.assertEqual(report.drift_class, "PASS")

    def test_small_drift_warn(self) -> None:
        base = _tensor_with_time(0.0)
        curr = _tensor_with_time(0.06)
        report = evaluate_drift(
            epoch_id="E2",
            baseline_epoch_id="B0",
            baseline_tensor=base,
            current_tensor=curr,
            invariant_violations=0,
            thresholds=self.thresholds,
        )
        self.assertEqual(report.drift_class, "WARN")

    def test_large_drift_fail(self) -> None:
        base = _tensor_with_time(0.0)
        curr = _tensor_with_time(0.2)
        report = evaluate_drift(
            epoch_id="E3",
            baseline_epoch_id="B0",
            baseline_tensor=base,
            current_tensor=curr,
            invariant_violations=0,
            thresholds=self.thresholds,
        )
        self.assertEqual(report.drift_class, "FAIL")

    def test_invariant_violation_forces_fail(self) -> None:
        base = _tensor_with_time(0.0)
        curr = _tensor_with_time(0.02)
        report = evaluate_drift(
            epoch_id="E4",
            baseline_epoch_id="B0",
            baseline_tensor=base,
            current_tensor=curr,
            invariant_violations=1,
            thresholds=self.thresholds,
        )
        self.assertEqual(report.drift_class, "FAIL")


if __name__ == "__main__":
    raise SystemExit(unittest.main())
