from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = ROOT / "04_PROD_TEMPLE_V2" / "src"
sys.path.insert(0, str(SRC_ROOT))
sys.path.insert(0, str(ROOT))

from core.runtime_registry import PolicyCDriftSpec  # noqa: E402
from memory.state_vault import StateVault  # noqa: E402
from policy_c.gates import run_drift_gate  # noqa: E402
from policy_c.pressure_tensor import PressureTensor, SCHEMA_ID  # noqa: E402


def _tensor(intensity: float) -> PressureTensor:
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


class TestPolicyCDriftGate(unittest.TestCase):
    def test_warn_emits_governance_and_passes(self) -> None:
        thresholds = PolicyCDriftSpec(l2_warn=0.05, l2_fail=0.10, max_fail=0.10)
        baseline = _tensor(0.0)
        current = _tensor(0.06)

        with tempfile_dir() as vault_path:
            vault = StateVault(path=vault_path)
            result = run_drift_gate(
                epoch_id="E1",
                baseline_epoch_id="B0",
                baseline_tensor=baseline,
                current_tensor=current,
                invariant_violations=0,
                thresholds=thresholds,
                vault=vault,
            )
            self.assertEqual(result.status, "PASS")
            self.assertEqual(result.drift_report.drift_class, "WARN")
            self.assertGreaterEqual(vault.record_count, 1)

    def test_fail_blocks_gate(self) -> None:
        thresholds = PolicyCDriftSpec(l2_warn=0.05, l2_fail=0.10, max_fail=0.10)
        baseline = _tensor(0.0)
        current = _tensor(0.2)

        with tempfile_dir() as vault_path:
            vault = StateVault(path=vault_path)
            result = run_drift_gate(
                epoch_id="E2",
                baseline_epoch_id="B0",
                baseline_tensor=baseline,
                current_tensor=current,
                invariant_violations=0,
                thresholds=thresholds,
                vault=vault,
            )
            self.assertEqual(result.status, "FAIL")
            self.assertEqual(result.drift_report.drift_class, "FAIL")
            self.assertGreaterEqual(vault.record_count, 1)


class tempfile_dir:
    def __enter__(self) -> Path:
        import tempfile

        self._dir = tempfile.TemporaryDirectory()
        return Path(self._dir.name) / "state_vault.jsonl"

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001, D401
        self._dir.cleanup()


if __name__ == "__main__":
    raise SystemExit(unittest.main())
