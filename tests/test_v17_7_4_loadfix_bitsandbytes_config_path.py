from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _core():
    path = ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py"
    spec = importlib.util.spec_from_file_location("kt_v1774_truegen_core_bnb", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_real_arm_config_declares_bitsandbytes_quantization_fields() -> None:
    config = json.loads((ROOT / "configs" / "v17_7_4" / "arm_model_config.json").read_text(encoding="utf-8"))
    assert config["base_model_repo"] == "Qwen/Qwen2.5-7B-Instruct"
    assert config["load_in_4bit"] is True
    assert config["bnb_4bit_quant_type"] == "nf4"
    assert config["bnb_4bit_compute_dtype"] in {"float16", "bfloat16"}
    assert config["bnb_4bit_use_double_quant"] is True


def test_standard_loader_path_does_not_add_quantization_config_when_disabled() -> None:
    core = _core()

    class FakeTorch:
        float16 = "fake-float16"

    kwargs, loader_mode = core.build_model_loader_kwargs(
        {"device_map": "auto", "load_in_4bit": False, "torch_dtype": "float16"},
        FakeTorch,
        bnb_config_cls=None,
    )
    assert loader_mode == core.MODEL_LOADER_AUTO_STANDARD
    assert kwargs["torch_dtype"] == "fake-float16"
    assert "quantization_config" not in kwargs
    assert "load_in_4bit" not in kwargs
