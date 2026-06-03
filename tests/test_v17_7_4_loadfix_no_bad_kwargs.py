from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _core():
    path = ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py"
    spec = importlib.util.spec_from_file_location("kt_v1774_truegen_core", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_runtime_never_forwards_load_in_4bit_as_bad_kwarg() -> None:
    source = (ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py").read_text(encoding="utf-8")
    forbidden_patterns = [
        'kwargs["load_in_4bit"]',
        "kwargs['load_in_4bit']",
        "from_pretrained(model_repo, load_in_4bit",
        "Qwen2ForCausalLM(",
    ]
    for pattern in forbidden_patterns:
        assert pattern not in source


def test_model_loader_kwargs_contract_rejects_bad_kwarg() -> None:
    core = _core()

    class FakeTorch:
        float16 = "fake-float16"
        bfloat16 = "fake-bfloat16"
        float32 = "fake-float32"

    class FakeBitsAndBytesConfig:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    kwargs, loader_mode = core.build_model_loader_kwargs(
        {
            "device_map": "auto",
            "load_in_4bit": True,
            "torch_dtype": "auto",
            "bnb_4bit_compute_dtype": "float16",
            "bnb_4bit_quant_type": "nf4",
            "bnb_4bit_use_double_quant": True,
        },
        FakeTorch,
        FakeBitsAndBytesConfig,
    )

    assert loader_mode == core.MODEL_LOADER_AUTO_BNB_4BIT
    assert "load_in_4bit" not in kwargs
    assert "quantization_config" in kwargs
    assert kwargs["quantization_config"].kwargs["load_in_4bit"] is True
    assert kwargs["quantization_config"].kwargs["bnb_4bit_quant_type"] == "nf4"
