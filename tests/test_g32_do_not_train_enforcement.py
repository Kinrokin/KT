from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    path = Path("scripts/enforce_do_not_train.py").resolve()
    scripts_dir = str(path.parent)
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    spec = importlib.util.spec_from_file_location("enforce_do_not_train", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_do_not_train_prefix_scoping_blocks_operational_training_without_self_deadlock() -> None:
    module = _load_module()

    assert module.is_training_like_path("adapters/new_adapter/model.safetensors")
    assert module.is_training_like_path("packets/ktg3_v3.zip")
    assert not module.is_training_like_path("schemas/kt.signal_density_row.schema.json")
    assert not module.is_training_like_path("tests/test_g32_signal_density_schema.py")
    assert not module.is_training_like_path("reports/g32_training_decision_receipt.json")
