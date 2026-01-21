from __future__ import annotations

import json
import unittest
from pathlib import Path


class TestDatasetRecordSchema(unittest.TestCase):
    def setUp(self) -> None:
        root = Path(__file__).resolve().parents[2]
        self.schema_path = root / "policy_c" / "policy_c_dataset_record_schema_v1.json"

    def test_schema_exists_and_is_strict(self) -> None:
        data = json.loads(self.schema_path.read_text(encoding="utf-8"))
        self.assertEqual(data.get("schema_id"), "kt.policy_c.dataset_record.v1")
        self.assertFalse(data.get("additionalProperties", True))


if __name__ == "__main__":
    raise SystemExit(unittest.main())
