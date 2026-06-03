from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _core():
    path = ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py"
    spec = importlib.util.spec_from_file_location("kt_v1774_truegen_core_adapter", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_adapter_path_resolution_and_sha_validation(tmp_path, monkeypatch) -> None:
    core = _core()
    adapter_dir = tmp_path / "adapters" / "learning_delta_lobe"
    adapter_dir.mkdir(parents=True)
    (adapter_dir / "adapter_config.json").write_text('{"peft_type":"LORA"}\n', encoding="utf-8")
    weight = adapter_dir / "adapter_model.safetensors"
    weight.write_bytes(b"adapter-weight-test")
    expected_sha = core.sha256_file(weight)
    monkeypatch.setenv("KT_TRUEGEN_ADAPTER_ROOT", str(tmp_path))

    config = json.loads((ROOT / "configs" / "v17_7_4" / "arm_model_config.json").read_text(encoding="utf-8"))
    config["adapter_source_preference"] = "LOCAL_PATH_FIRST"
    arm = next(arm for arm in config["arms"] if arm["arm_id"] == "route_regret_policy_adapter_global")
    arm["adapter_path"] = "${KT_TRUEGEN_ADAPTER_ROOT}/adapters/learning_delta_lobe"
    arm["adapter_sha256_optional"] = expected_sha

    assert core.adapter_ref_for_arm(arm, config) == str(adapter_dir)
    receipt = core.validate_adapter_source(arm, config)
    assert receipt["adapter_source_status"] == "LOCAL_ADAPTER_SOURCE_VALIDATED"
    assert receipt["adapter_sha256_verified"] is True


def test_missing_adapter_path_fails_closed(tmp_path, monkeypatch) -> None:
    core = _core()
    monkeypatch.setenv("KT_TRUEGEN_ADAPTER_ROOT", str(tmp_path))
    config = json.loads((ROOT / "configs" / "v17_7_4" / "arm_model_config.json").read_text(encoding="utf-8"))
    config["adapter_source_preference"] = "LOCAL_PATH_FIRST"
    arm = next(arm for arm in config["arms"] if arm["arm_id"] == "formal_math_repair_adapter_global")
    arm["adapter_hf_repo"] = ""
    arm["adapter_path"] = "${KT_TRUEGEN_ADAPTER_ROOT}/missing/formal_proof_reasoning_lobe"
    try:
        core.validate_adapter_source(arm, config)
    except RuntimeError as exc:
        assert "adapter path missing" in str(exc)
    else:
        raise AssertionError("missing real adapter path must fail closed")


def test_hf_adapter_load_uses_subfolder_when_local_root_absent(monkeypatch) -> None:
    core = _core()
    monkeypatch.delenv("KT_TRUEGEN_ADAPTER_ROOT", raising=False)
    monkeypatch.delenv("KT_TRUEGEN_ADAPTER_SOURCE", raising=False)
    config = json.loads((ROOT / "configs" / "v17_7_4" / "arm_model_config.json").read_text(encoding="utf-8"))
    arm = next(arm for arm in config["arms"] if arm["arm_id"] == "route_regret_policy_adapter_global")

    assert core.adapter_source_kind_for_arm(arm, config) == core.ADAPTER_SOURCE_HF_VAULT
    assert core.adapter_ref_for_arm(arm, config) == arm["adapter_hf_repo"]
    assert core.adapter_load_kwargs_for_arm(arm, config) == {"subfolder": "adapters/learning_delta_lobe"}


def test_hf_adapter_root_only_load_is_forbidden(monkeypatch) -> None:
    core = _core()
    monkeypatch.delenv("KT_TRUEGEN_ADAPTER_ROOT", raising=False)
    monkeypatch.delenv("KT_TRUEGEN_ADAPTER_SOURCE", raising=False)
    config = json.loads((ROOT / "configs" / "v17_7_4" / "arm_model_config.json").read_text(encoding="utf-8"))
    arm = next(arm for arm in config["arms"] if arm["arm_id"] == "formal_math_repair_adapter_global")
    arm.pop("adapter_hf_subfolder", None)

    try:
        core.adapter_load_kwargs_for_arm(arm, config)
    except RuntimeError as exc:
        assert "HF adapter subfolder missing" in str(exc)
    else:
        raise AssertionError("HF adapter root-only load must fail before PEFT")
