from __future__ import annotations

import importlib.util
import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _core():
    path = ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py"
    spec = importlib.util.spec_from_file_location("kt_v1774_truegen_core_memory", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _test_config(core, row_limit: int = 2) -> dict:
    return {
        "base_model_repo": "__KT_LOCAL_TEST_BACKEND__",
        "load_in_4bit": False,
        "torch_dtype": "auto",
        "max_new_tokens": 8,
        "batch_size": 1,
        "device_map": "cpu",
        "generation_seed": 7,
        "row_limit": row_limit,
        "stream_rows_to_disk": True,
        "arm_isolation_mode": "ARM_MAJOR_UNLOAD_AFTER_EACH_ARM",
        "arms": [
            {
                "arm_id": arm,
                "model_repo_or_base": "__KT_LOCAL_TEST_BACKEND__",
                "adapter_hf_repo": "",
                "adapter_path": "",
                "adapter_sha256_optional": "",
                "enabled": True,
                "prompt_template_id": "raw",
                "scoring_method": "contains_expected_label",
                "max_new_tokens": 8,
            }
            for arm in core.ARM_IDS
        ],
    }


def test_real_config_uses_hf_vault_subfolders_when_no_local_root(monkeypatch) -> None:
    core = _core()
    monkeypatch.delenv("KT_TRUEGEN_ADAPTER_ROOT", raising=False)
    monkeypatch.delenv("KT_TRUEGEN_ADAPTER_SOURCE", raising=False)
    config = json.loads((ROOT / "configs" / "v17_7_4" / "arm_model_config.json").read_text(encoding="utf-8"))
    assert config["adapter_source_preference"] == "HF_VAULT_FIRST"
    assert config["hf_vault_adapter_required"] is True
    for arm in config["arms"]:
        if arm["arm_id"] not in core.ADAPTER_ARM_IDS:
            continue
        assert core.adapter_source_kind_for_arm(arm, config) == core.ADAPTER_SOURCE_HF_VAULT
        assert core.adapter_ref_for_arm(arm, config) == "Kinrokin/kt13-full-e2e-final-only-20260524-174447"
        assert core.adapter_load_kwargs_for_arm(arm, config)["subfolder"].startswith("adapters/")
        receipt = core.validate_adapter_source(arm, config)
        assert receipt["adapter_source_status"] == "HF_ADAPTER_SOURCE_BOUND_RUNTIME_LOAD_REQUIRED"
        assert receipt["hf_vault_source_of_truth"] is True


def test_real_config_prefers_normalized_local_adapter_root_when_present(tmp_path, monkeypatch) -> None:
    core = _core()
    monkeypatch.setenv("KT_TRUEGEN_ADAPTER_ROOT", str(tmp_path))
    monkeypatch.setenv("KT_TRUEGEN_ADAPTER_SOURCE", "hf")
    config = json.loads((ROOT / "configs" / "v17_7_4" / "arm_model_config.json").read_text(encoding="utf-8"))

    for arm in config["arms"]:
        if arm["arm_id"] not in core.ADAPTER_ARM_IDS:
            continue
        expected = arm["expected_adapter_id"]
        assert core.adapter_source_kind_for_arm(arm, config) == core.ADAPTER_SOURCE_LOCAL_PATH
        assert core.adapter_ref_for_arm(arm, config) == str(tmp_path / "adapters" / expected)
        assert core.adapter_load_kwargs_for_arm(arm, config) == {}


def test_row_ladder_defaults_to_three_for_memory_safe_entry() -> None:
    core = _core()
    config = json.loads((ROOT / "configs" / "v17_7_4" / "arm_model_config.json").read_text(encoding="utf-8"))
    row_limit, receipt = core.resolve_effective_row_limit(config)
    assert row_limit == 3
    assert receipt["row_ladder"] == [3, 10, 25, 50, 100]
    assert receipt["row_limit_source"] == "config.default_row_ladder_stage"


def test_runner_streams_rows_and_memory_ledger_arm_major(tmp_path, monkeypatch) -> None:
    core = _core()
    runtime_root = tmp_path / "runtime"
    inputs = runtime_root / "runtime_inputs"
    inputs.mkdir(parents=True)
    manifest = json.loads((ROOT / "admission" / "v17_7_4_truegen_row_manifest.json").read_text(encoding="utf-8"))
    manifest["rows"] = manifest["rows"][:2]
    manifest["row_count"] = 2
    (inputs / "truegen_row_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (inputs / "arm_model_config.json").write_text(json.dumps(_test_config(core, row_limit=2)), encoding="utf-8")
    monkeypatch.setenv("KT_TRUEGEN_ALLOW_TEST_BACKEND", "1")
    monkeypatch.setenv("KT_OUTPUT_DIR", str(tmp_path / "out"))

    summary = core.run_truegen_runtime(runtime_root)

    assert summary["status"] == "PASS"
    rows = core.read_jsonl(tmp_path / "out" / "truegen_arm_result_matrix.jsonl")
    ledger = core.read_jsonl(tmp_path / "out" / "gpu_memory_ledger.jsonl")
    assert len(rows) == len(core.ARM_IDS) * 2
    assert {row["label"] for row in ledger} >= {"run_start", "arm_start", "arm_unloaded", "run_end"}
    assert sum(1 for row in ledger if row["label"] == "arm_start") == len(core.ARM_IDS)
    assert (tmp_path / "out" / "streaming_generation_receipt.json").exists()
    assert (tmp_path / "out" / "partial_output_rescue_receipt.json").exists()
    assert (tmp_path / "out" / "assessment_only_packaging_receipt.json").exists()


def test_blocked_runtime_preserves_partial_rows_and_assessment(tmp_path, monkeypatch) -> None:
    core = _core()
    runtime_root = tmp_path / "runtime"
    inputs = runtime_root / "runtime_inputs"
    inputs.mkdir(parents=True)
    manifest = json.loads((ROOT / "admission" / "v17_7_4_truegen_row_manifest.json").read_text(encoding="utf-8"))
    manifest["rows"] = manifest["rows"][:2]
    manifest["row_count"] = 2
    (inputs / "truegen_row_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (inputs / "arm_model_config.json").write_text(json.dumps(_test_config(core, row_limit=2)), encoding="utf-8")
    monkeypatch.setenv("KT_TRUEGEN_ALLOW_TEST_BACKEND", "1")
    monkeypatch.setenv("KT_OUTPUT_DIR", str(tmp_path / "out"))

    original = core.GenerationBackend.generate
    calls = {"count": 0}

    def flaky(self, prompt, arm, config, row):
        calls["count"] += 1
        if calls["count"] == 2:
            raise RuntimeError("forced memory-style failure")
        return original(self, prompt, arm, config, row)

    monkeypatch.setattr(core.GenerationBackend, "generate", flaky)
    summary = core.run_truegen_runtime(runtime_root)

    assert summary["status"] == "BLOCKED"
    blocker = json.loads((tmp_path / "out" / "BLOCKER_RECEIPT.json").read_text(encoding="utf-8"))
    rescue = json.loads((tmp_path / "out" / "partial_output_rescue_receipt.json").read_text(encoding="utf-8"))
    assert blocker["partial_rows_preserved"] == 1
    assert rescue["partial_rows_preserved"] == 1
    assessment = tmp_path / "out" / "KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip"
    assert assessment.exists()
    with zipfile.ZipFile(assessment) as archive:
        names = set(archive.namelist())
    assert "truegen_arm_result_matrix.jsonl" in names
    assert "partial_output_rescue_receipt.json" in names
    assert "BLOCKER_RECEIPT.json" in names
