from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _core():
    path = ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py"
    spec = importlib.util.spec_from_file_location("kt_v1774_truegen_core_tiny", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_tiny_gpt2_cannot_request_real_arm_authority() -> None:
    core = _core()
    config = json.loads((ROOT / "configs" / "v17_7_4" / "arm_model_config.json").read_text(encoding="utf-8"))
    config["base_model_repo"] = "sshleifer/tiny-gpt2"
    defects = core.validate_arm_model_config(config)
    assert "real_arm_base_model_must_not_be_smoke:sshleifer/tiny-gpt2" in defects
