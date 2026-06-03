from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _core():
    path = ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py"
    spec = importlib.util.spec_from_file_location("kt_v1774_truegen_core_realbench", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _test_config(core, row_limit: int = 100, measurement_mode: str = "REAL_BENCHMARK_GAUGE") -> dict:
    return {
        "base_model_repo": "__KT_LOCAL_TEST_BACKEND__",
        "load_in_4bit": False,
        "torch_dtype": "auto",
        "max_new_tokens": 8,
        "batch_size": 1,
        "device_map": "cpu",
        "generation_seed": 7,
        "row_limit": row_limit,
        "measurement_mode": measurement_mode,
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
                "scoring_method": "exact_normalized",
                "max_new_tokens": 8,
            }
            for arm in core.ARM_IDS
        ],
    }


def _real_row(index: int = 0) -> dict:
    answer = str(18 + index)
    question = f"What is {9 + index} plus 9?"
    return {
        "schema_id": "kt.v17_7_4.truegen_row.v1",
        "sample_id": f"realbench:{index}",
        "dataset": "unit_math",
        "split": "test",
        "task_family": "formal_math",
        "benchmark_source": "REAL_BENCHMARK_ROW",
        "question_text": question,
        "expected_answer": answer,
        "expected_label_or_oracle_label": answer,
        "answer_type": "numeric_final_answer",
        "answer_format_contract": "Emit only the final number.",
        "prompt": question,
        "prompt_hash": core_hash(question),
        "label_source": "PUBLIC_BENCHMARK_GROUND_TRUTH",
        "scoring_rule": "exact_normalized",
        "holdout_status": "HELDOUT_NOT_FOR_PROMOTION",
        "evidence_band": "REAL_BENCHMARK_GAUGE",
        "route_boundary_class": "REAL_BENCHMARK_GAUGE",
        "source_replay_reference_if_any": {},
        "claim_ceiling_preserved": True,
        "promotion_authority": False,
        "runtime_authority": False,
        "adapter_training_authorized": False,
        "router_training_authorized": False,
        "policy_optimization_authorized": False,
        "learned_router_superiority_claim": False,
        "v18_runtime_authority": False,
    }


def core_hash(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_env_row_override_25_is_honored(monkeypatch) -> None:
    core = _core()
    config = _test_config(core, row_limit=100)
    monkeypatch.setenv("KT_TRUEGEN_TARGET_ROWS", "25")
    row_limit, receipt = core.resolve_effective_row_limit(config)
    assert row_limit == 25
    assert receipt["requested_row_limit"] == 25
    assert receipt["effective_row_limit"] == 25
    assert receipt["row_limit_source"] == "KT_TRUEGEN_TARGET_ROWS"
    assert receipt["row_limit_honored"] is True


def test_default_three_only_applies_without_env_override(monkeypatch) -> None:
    core = _core()
    config = json.loads((ROOT / "configs" / "v17_7_4" / "arm_model_config.json").read_text(encoding="utf-8"))
    for name in [*core.ROW_REQUEST_ENVS, "KT_TRUEGEN_LADDER_STAGE"]:
        monkeypatch.delenv(name, raising=False)
    row_limit, receipt = core.resolve_effective_row_limit(config)
    assert row_limit == 3
    assert receipt["row_limit_source"] == "config.default_row_ladder_stage"
    assert receipt["row_limit_honored"] is True


def test_env_override_mismatch_blocks_in_receipt(monkeypatch) -> None:
    core = _core()
    config = _test_config(core, row_limit=10)
    monkeypatch.setenv("KT_TRUEGEN_TARGET_ROWS", "25")
    row_limit, receipt = core.resolve_effective_row_limit(config)
    assert row_limit == 10
    assert receipt["status"] == "BLOCKED"
    assert receipt["row_limit_honored"] is False
    assert "exceeds config.row_limit" in receipt["reason_if_not_honored"]


def test_real_benchmark_rows_require_question_and_expected_answer() -> None:
    core = _core()
    config = _test_config(core)
    good = {"rows": [_real_row()]}
    receipt = core.validate_benchmark_source_integrity(good, config)
    assert receipt["status"] == "PASS"

    bad = _real_row()
    bad.pop("question_text")
    bad["prompt"] = "Fresh-generation diagnostic boundary row. dataset=gsm8k; boundaries=route."
    bad["sample_id"] = "v1773-acq-0001"
    receipt = core.validate_benchmark_source_integrity({"rows": [bad]}, config)
    assert receipt["status"] == "BLOCKED"
    assert "question_text_missing" in receipt["defects"][0]["defects"]
    assert "prompt_contains_only_metadata" in receipt["defects"][0]["defects"]


def test_prompt_manifest_keeps_expected_answer_scorer_only() -> None:
    core = _core()
    config = _test_config(core)
    manifest = {"rows": [_real_row()]}
    prompt_rows = core.build_prompt_manifest_rows(manifest, config)
    receipt = core.validate_prompt_integrity(prompt_rows, config)
    assert receipt["status"] == "PASS"
    assert prompt_rows
    assert all(row["prompt_contains_question_text"] is True for row in prompt_rows)
    assert all(row["expected_answer_present"] is True for row in prompt_rows)
    assert all(row["expected_answer_visible_to_model"] is False for row in prompt_rows)
    assert all(row["prompt_contains_expected_answer_for_scoring_only"] is True for row in prompt_rows)


def test_runtime_emits_prompt_and_source_integrity_receipts(tmp_path, monkeypatch) -> None:
    core = _core()
    runtime_root = tmp_path / "runtime"
    inputs = runtime_root / "runtime_inputs"
    inputs.mkdir(parents=True)
    manifest = {"schema_id": "kt.v17_7_4.realbench_row_manifest.v1", "row_count": 2, "rows": [_real_row(0), _real_row(1)]}
    (inputs / "truegen_row_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (inputs / "arm_model_config.json").write_text(json.dumps(_test_config(core, row_limit=2)), encoding="utf-8")
    monkeypatch.setenv("KT_TRUEGEN_ALLOW_TEST_BACKEND", "1")
    monkeypatch.setenv("KT_TRUEGEN_MEASUREMENT_MODE", "REAL_BENCHMARK_GAUGE")
    monkeypatch.setenv("KT_TRUEGEN_TARGET_ROWS", "2")
    monkeypatch.setenv("KT_OUTPUT_DIR", str(tmp_path / "out"))

    summary = core.run_truegen_runtime(runtime_root)

    assert summary["status"] == "PASS"
    prompt_rows = core.read_jsonl(tmp_path / "out" / "truegen_prompt_manifest.jsonl")
    assert len(prompt_rows) == 2 * len(core.ARM_IDS)
    assert json.loads((tmp_path / "out" / "v17_7_4_row_authority_receipt.json").read_text())["row_limit_honored"] is True
    assert json.loads((tmp_path / "out" / "v17_7_4_benchmark_source_integrity_receipt.json").read_text())["status"] == "PASS"
    assert json.loads((tmp_path / "out" / "v17_7_4_prompt_integrity_receipt.json").read_text())["status"] == "PASS"


def test_g2_sentinel_blocks_without_exact_source_manifest(tmp_path) -> None:
    core = _core()
    receipt = core.g2_sentinel_manifest_receipt(tmp_path)
    assert receipt["status"] == "BLOCKED"
    assert receipt["outcome"] == "KT_BLOCKED__G2_SENTINEL_SOURCE_MISSING"
