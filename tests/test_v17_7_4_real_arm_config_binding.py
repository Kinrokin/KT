from __future__ import annotations

import importlib.util
import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _core():
    path = ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py"
    spec = importlib.util.spec_from_file_location("kt_v1774_truegen_core", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_real_arm_config_uses_qwen_and_bound_adapter_sources() -> None:
    core = _core()
    config = json.loads((ROOT / "configs" / "v17_7_4" / "arm_model_config.json").read_text())
    assert core.validate_arm_model_config(config) == []
    assert config["real_arm_authority_requested"] is True
    assert config["config_profile"] == "REAL_ARM"
    assert config["base_model_repo"] == "Qwen/Qwen2.5-7B-Instruct"
    assert config["base_model_repo"] != "sshleifer/tiny-gpt2"
    adapter_arms = [arm for arm in config["arms"] if arm["arm_id"] in core.ADAPTER_ARM_IDS]
    assert adapter_arms
    for arm in adapter_arms:
        assert arm["enabled"] is True
        assert arm["adapter_binding_status"] == "REAL_ADAPTER_SOURCE_BOUND"
        assert arm["adapter_path"]
        assert arm["adapter_sha256_optional"]


def test_smoke_config_cannot_satisfy_required_real_arm_runtime(monkeypatch) -> None:
    core = _core()
    config = json.loads((ROOT / "configs" / "v17_7_4" / "arm_model_config.example.json").read_text())
    monkeypatch.setenv("KT_TRUEGEN_REQUIRE_REAL_ARM_CONFIG", "1")
    defects = core.validate_arm_model_config(config)
    assert "KT_TRUEGEN_REQUIRE_REAL_ARM_CONFIG set but config is not real-arm authority config" in defects


def test_real_arm_config_fails_if_adapter_source_removed() -> None:
    core = _core()
    config = json.loads((ROOT / "configs" / "v17_7_4" / "arm_model_config.json").read_text())
    for arm in config["arms"]:
        if arm["arm_id"] == "formal_math_repair_adapter_global":
            arm["adapter_path"] = ""
    defects = core.validate_arm_model_config(config)
    assert any("real_arm_missing_adapter_source:formal_math_repair_adapter_global" in defect for defect in defects)


def test_real_arm_packet_bundles_real_config_not_smoke_config_as_runtime_input() -> None:
    packet = ROOT / "packets" / "ktv1774_real_arm_truegen_v1.zip"
    assert packet.exists()
    with zipfile.ZipFile(packet) as archive:
        config = json.loads(archive.read("runtime_inputs/arm_model_config.json").decode("utf-8"))
        names = archive.namelist()
        text = "\n".join(
            archive.read(name).decode("utf-8", errors="ignore")
            for name in names
            if name.endswith((".json", ".py", ".md"))
        )
    assert config["real_arm_authority_requested"] is True
    assert config["base_model_repo"] == "Qwen/Qwen2.5-7B-Instruct"
    assert "sshleifer/tiny-gpt2" in text
    assert "runtime_inputs/arm_model_config.example.json" in names
