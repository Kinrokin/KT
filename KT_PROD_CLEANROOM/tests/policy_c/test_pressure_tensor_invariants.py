from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from policy_c.pressure_tensor import PressureTensor, SCHEMA_ID, single_axis_sweep  # noqa: E402


def _tensor_payload() -> dict:
    axes = {
        "time": {"intensity": 0.1, "enabled": True},
        "universe": {"intensity": 0.2, "enabled": True},
        "language": {"intensity": 0.3, "enabled": True},
        "hop": {"intensity": 0.4, "enabled": True},
        "step": {"intensity": 0.5, "enabled": True},
        "paradox": {"intensity": 0.6, "enabled": True},
        "puzzle": {"intensity": 0.7, "enabled": True},
    }
    projection = {
        "rule": "weighted_sum",
        "weights": {
            "time": 0.1,
            "universe": 0.1,
            "language": 0.1,
            "hop": 0.1,
            "step": 0.1,
            "paradox": 0.1,
            "puzzle": 0.1,
        },
        "clamp_min": 0.0,
        "clamp_max": 1.0,
    }
    invariants = {"reversible": True, "isolated": True, "no_cross_axis_bleed": True}
    return {"schema_id": SCHEMA_ID, "axes": axes, "projection": projection, "invariants": invariants}


class TestPressureTensorInvariants(unittest.TestCase):
    def test_cxb_1_single_axis_sweep(self) -> None:
        tensor = PressureTensor.from_dict(_tensor_payload())
        base = tensor.pressure_contributions()
        swept = single_axis_sweep(tensor, axis="time", intensity=0.9)
        after = swept.pressure_contributions()

        self.assertNotEqual(base["time"], after["time"])
        for axis in base:
            if axis == "time":
                continue
            self.assertEqual(base[axis], after[axis])

    def test_projection_determinism(self) -> None:
        tensor = PressureTensor.from_dict(_tensor_payload())
        self.assertEqual(tensor.pressure_scalar(), tensor.pressure_scalar())
        self.assertEqual(tensor.projection_hash(), tensor.projection_hash())

    def test_hash_stability_float_format(self) -> None:
        payload = _tensor_payload()
        payload["projection"]["weights"]["time"] = 0.10
        tensor = PressureTensor.from_dict(payload)
        hash_a = tensor.projection_hash()
        hash_b = tensor.projection_hash()
        self.assertEqual(hash_a, hash_b)

    def test_unknown_key_rejection(self) -> None:
        payload = _tensor_payload()
        payload["axes"]["unknown_axis"] = {"intensity": 0.2, "enabled": True}
        with self.assertRaises(ValueError):
            PressureTensor.from_dict(payload)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
