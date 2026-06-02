from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _core():
    path = ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py"
    spec = importlib.util.spec_from_file_location("kt_v1774_truegen_core", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_arm_model_config_example_satisfies_contract() -> None:
    config = json.loads((ROOT / "configs" / "v17_7_4" / "arm_model_config.example.json").read_text())
    defects = _core().validate_arm_model_config(config)
    assert defects == []
    assert {arm["arm_id"] for arm in config["arms"]} == set(_core().ARM_IDS)
    assert config["adapter_training_authorized"] is False
    assert config["claim_ceiling_preserved"] is True
