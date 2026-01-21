from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


class TestPolicyCDriftSchema(unittest.TestCase):
    def setUp(self) -> None:
        root = Path(__file__).resolve().parents[2]
        self.schema_path = root / "policy_c" / "schemas" / "policy_c_drift_report_schema_v1.json"

    def test_schema_exists_and_is_strict(self) -> None:
        self.assertTrue(self.schema_path.exists())
        schema = json.loads(self.schema_path.read_text(encoding="utf-8"))
        self.assertEqual(schema.get("schema_id"), "kt.policy_c.drift_report.v1")
        self.assertFalse(schema.get("additionalProperties", True))
        required = set(schema.get("required", []))
        expected = {
            "epoch_id",
            "baseline_epoch_id",
            "pressure_delta_l2",
            "pressure_delta_max",
            "invariant_violations",
            "drift_class",
            "reason_codes",
            "timestamp",
        }
        self.assertEqual(required, expected)

    def test_schema_deterministic_serialization(self) -> None:
        schema = json.loads(self.schema_path.read_text(encoding="utf-8"))
        serialized = json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        serialized_again = json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        self.assertEqual(serialized, serialized_again)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
