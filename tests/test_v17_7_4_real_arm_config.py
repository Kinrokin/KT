from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _core():
    path = ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py"
    spec = importlib.util.spec_from_file_location("kt_v1774_truegen_core_realarm", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_real_arm_config_passes_repo_contract() -> None:
    core = _core()
    config = json.loads((ROOT / "configs" / "v17_7_4" / "arm_model_config.json").read_text(encoding="utf-8"))
    assert core.validate_arm_model_config(config) == []
    assert config["real_arm_authority_requested"] is True
    assert config["smoke_config"] is False
    assert config["base_model_repo"] in core.INTENDED_REAL_BASE_MODELS
