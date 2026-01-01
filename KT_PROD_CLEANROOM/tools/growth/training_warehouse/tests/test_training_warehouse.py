from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import sys


def _add_wh_to_syspath() -> None:
    # .../tools/growth/training_warehouse/tests/test_training_warehouse.py -> .../tools/growth/training_warehouse
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))


_add_wh_to_syspath()

from warehouse_schemas import TrainingExemplarSchema  # noqa: E402
from warehouse_store import append_exemplar_to_warehouse  # noqa: E402


class TestTrainingWarehouse(unittest.TestCase):
    def test_exemplar_hash_deterministic(self) -> None:
        ex1 = TrainingExemplarSchema.make(
            kernel_target="V2_SOVEREIGN",
            epoch_id="E1",
            crucible_id="CRU-1",
            run_id=("a" * 64),
            provenance={"artifacts_dir": "x", "replay_head_hash": "y", "record_count": 1, "governance_types": "G"},
            extraction_justification="x",
            license="INTERNAL_ONLY",
            usage_flags={"allow_training": True, "allow_distillation": True},
            content={"prompt": "hello", "expected_outcome": "PASS", "notes": ""},
        )
        ex2 = TrainingExemplarSchema.make(
            kernel_target="V2_SOVEREIGN",
            epoch_id="E1",
            crucible_id="CRU-1",
            run_id=("a" * 64),
            provenance={"artifacts_dir": "x", "replay_head_hash": "y", "record_count": 1, "governance_types": "G"},
            extraction_justification="x",
            license="INTERNAL_ONLY",
            usage_flags={"allow_training": True, "allow_distillation": True},
            content={"prompt": "hello", "expected_outcome": "PASS", "notes": ""},
        )
        self.assertEqual(ex1.exemplar_hash, ex2.exemplar_hash)

    def test_append_only_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            artifacts = root / "artifacts"
            artifacts.mkdir(parents=True, exist_ok=True)
            exemplar_path = artifacts / "exemplars" / f"{'b'*64}.json"
            exemplar_path.parent.mkdir(parents=True, exist_ok=True)

            exemplar = TrainingExemplarSchema.make(
                kernel_target="V2_SOVEREIGN",
                epoch_id="E1",
                crucible_id="CRU-1",
                run_id=("a" * 64),
                provenance={"artifacts_dir": "x", "replay_head_hash": "y", "record_count": 1, "governance_types": "G"},
                extraction_justification="x",
                license="INTERNAL_ONLY",
                usage_flags={"allow_training": True, "allow_distillation": True},
                content={"prompt": "hello", "expected_outcome": "PASS", "notes": ""},
            )
            exemplar_path.write_text(json.dumps(exemplar.to_dict(), sort_keys=True), encoding="utf-8")

            appended_1 = append_exemplar_to_warehouse(artifacts_root=artifacts, exemplar_path=exemplar_path)
            appended_2 = append_exemplar_to_warehouse(artifacts_root=artifacts, exemplar_path=exemplar_path)
            self.assertTrue(appended_1)
            self.assertFalse(appended_2)

            manifest = (artifacts / "warehouse_manifest.jsonl").read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(manifest), 1)

    def test_unknown_content_key_rejected(self) -> None:
        with self.assertRaises(ValueError):
            TrainingExemplarSchema.make(
                kernel_target="V2_SOVEREIGN",
                epoch_id="E1",
                crucible_id="CRU-1",
                run_id=("a" * 64),
                provenance={"artifacts_dir": "x", "replay_head_hash": "y", "record_count": 1, "governance_types": "G"},
                extraction_justification="x",
                license="INTERNAL_ONLY",
                usage_flags={"allow_training": True, "allow_distillation": True},
                content={"prompt": "hello", "expected_outcome": "PASS", "notes": "", "stdout": "nope"},
            )


if __name__ == "__main__":
    raise SystemExit(unittest.main())
