from __future__ import annotations

import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_stop50_runner_uses_embedded_quantization_not_runtime_bitsandbytes_config() -> None:
    with zipfile.ZipFile(ROOT / "packets/ktstop50_v1.zip") as zf:
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8-sig")
        config = json.loads(zf.read("runtime/ktstop50_config.json").decode("utf-8-sig"))
    assert "AutoModelForCausalLM.from_pretrained" in runner
    assert "BitsAndBytesConfig" not in runner
    assert config["base_model_repo"] == "unsloth/Qwen2.5-7B-Instruct-bnb-4bit"
