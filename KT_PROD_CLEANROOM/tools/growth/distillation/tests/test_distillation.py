from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import sys


def _add_distill_to_syspath() -> None:
    # .../tools/growth/distillation/tests/test_distillation.py -> .../tools/growth/distillation
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))


_add_distill_to_syspath()

from distill_schemas import DistillationConfigSchema, ModelArtifactSchema, TrainingRunManifestSchema, sha256_json  # noqa: E402


class TestDistillation(unittest.TestCase):
    def test_deterministic_run_id(self) -> None:
        cfg = DistillationConfigSchema.make(config_id="X", max_exemplars=10, toolchain={"name": "T", "version": "1", "notes": ""})
        run_id_1 = sha256_json({"config_hash": cfg.config_hash, "warehouse_manifest": "m", "exemplar_ids": ["a"]})
        run_id_2 = sha256_json({"config_hash": cfg.config_hash, "warehouse_manifest": "m", "exemplar_ids": ["a"]})
        self.assertEqual(run_id_1, run_id_2)

    def test_artifact_hash_stable(self) -> None:
        cfg = DistillationConfigSchema.make(config_id="X", max_exemplars=10, toolchain={"name": "T", "version": "1", "notes": ""})
        run = TrainingRunManifestSchema.make(
            run_id=("a" * 64),
            config=cfg,
            warehouse_manifest_path="m",
            exemplar_ids=["b" * 64],
            exemplar_hashes=["c" * 64],
        )
        art1 = ModelArtifactSchema.make(run_manifest=run)
        art2 = ModelArtifactSchema.make(run_manifest=run)
        self.assertEqual(art1.artifact_hash, art2.artifact_hash)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
