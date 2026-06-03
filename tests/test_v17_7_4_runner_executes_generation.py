from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _core():
    path = ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py"
    spec = importlib.util.spec_from_file_location("kt_v1774_truegen_core", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _test_config(core) -> dict:
    return {
        "base_model_repo": "__KT_LOCAL_TEST_BACKEND__",
        "load_in_4bit": False,
        "torch_dtype": "auto",
        "max_new_tokens": 8,
        "batch_size": 1,
        "device_map": "cpu",
        "generation_seed": 7,
        "row_limit": 2,
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


def test_runner_executes_fresh_generation_contract_with_local_test_backend(tmp_path, monkeypatch) -> None:
    core = _core()
    runtime_root = tmp_path / "runtime"
    inputs = runtime_root / "runtime_inputs"
    inputs.mkdir(parents=True)
    manifest = json.loads((ROOT / "admission" / "v17_7_4_truegen_row_manifest.json").read_text())
    manifest["rows"] = manifest["rows"][:2]
    manifest["row_count"] = 2
    (inputs / "truegen_row_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (inputs / "arm_model_config.json").write_text(json.dumps(_test_config(core)), encoding="utf-8")
    monkeypatch.setenv("KT_TRUEGEN_ALLOW_TEST_BACKEND", "1")
    monkeypatch.setenv("KT_OUTPUT_DIR", str(tmp_path / "out"))
    summary = core.run_truegen_runtime(runtime_root)
    assert summary["status"] == "PASS"
    assert summary["measurement_source"] == core.FRESH_SOURCE
    assert summary["generation_artifacts_present"] is True
    rows = core.read_jsonl(tmp_path / "out" / "truegen_arm_result_matrix.jsonl")
    assert len(rows) == len(core.ARM_IDS) * 2
    assert {row["measurement_status"] for row in rows} == {core.FRESH_STATUS}
    assert {row["measurement_source"] for row in rows} == {core.FRESH_SOURCE}
    assert all(row["prompt_hash"] and row["output_hash"] and row["generation_artifacts_present"] for row in rows)
    assert all("total_tokens" in row and "verified_work_per_token" in row and "bloat_class" in row for row in rows)
    assert (tmp_path / "out" / "g2_compression_anchor_receipt.json").exists()
    assert (tmp_path / "out" / "truegen_compression_frontier_gate.json").exists()
    assert (tmp_path / "out" / "truegen_verified_work_per_token_scorecard.json").exists()
    assert (tmp_path / "out" / "KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip").exists()
