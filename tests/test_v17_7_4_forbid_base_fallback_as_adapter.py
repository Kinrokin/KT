from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _core():
    path = ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py"
    spec = importlib.util.spec_from_file_location("kt_v1774_truegen_core_basefallback", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_adapter_arm_without_source_is_not_adapter_evidence() -> None:
    core = _core()
    config = json.loads((ROOT / "configs" / "v17_7_4" / "arm_model_config.json").read_text(encoding="utf-8"))
    arm = next(arm for arm in config["arms"] if arm["arm_id"] == "math_act_adapter_global")
    arm["adapter_path"] = ""
    arm["adapter_hf_repo"] = ""
    defects = core.validate_arm_model_config(config)
    assert any("real_arm_missing_adapter_source:math_act_adapter_global" in defect for defect in defects)
