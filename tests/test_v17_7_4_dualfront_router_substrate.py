from __future__ import annotations

import importlib.util
import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _core():
    path = ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py"
    spec = importlib.util.spec_from_file_location("kt_v1774_truegen_core_dualfront", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _mc_row() -> dict:
    return {
        "schema_id": "kt.v17_7_4.truegen_row.v1",
        "sample_id": "dualfront:mc",
        "dataset": "ARC-Challenge",
        "split": "test",
        "task_family": "science_reasoning",
        "benchmark_source": "REAL_BENCHMARK_ROW",
        "question_text": "Which option is correct?\nA. Alpha\nB. Beta\nC. Gamma\nD. Delta",
        "expected_answer": "C",
        "expected_label_or_oracle_label": "C",
        "answer_type": "multiple_choice_letter",
        "answer_format_contract": "Emit only the option letter.",
        "prompt": "x",
        "prompt_hash": "x",
        "label_source": "PUBLIC_BENCHMARK_GROUND_TRUTH",
        "scoring_rule": "multiple_choice_letter",
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


def _math_row() -> dict:
    row = _mc_row()
    row.update(
        sample_id="dualfront:gsm8k",
        dataset="GSM8K",
        task_family="formal_math",
        question_text="A shop has 2 packs of 3 pencils. How many pencils?",
        expected_answer="6",
        expected_label_or_oracle_label="6",
        answer_type="numeric_final_answer",
        answer_format_contract="Emit only the normalized number.",
    )
    return row


def _config(core) -> dict:
    return {
        "base_model_repo": "__KT_LOCAL_TEST_BACKEND__",
        "load_in_4bit": False,
        "torch_dtype": "auto",
        "max_new_tokens": 8,
        "batch_size": 1,
        "device_map": "cpu",
        "generation_seed": 7,
        "row_limit": 2,
        "measurement_mode": "DUALFRONT_REASONING_PRESERVING_ADMISSION_BENCH",
        "compact_answer_contract": True,
        "reasoning_preserving_compact": True,
        "stream_rows_to_disk": True,
        "required_arm_ids": ["A0_base_raw", "A3_math_act_reasoning_preserving_compact"],
        "arms": [
            {
                "arm_id": "A0_base_raw",
                "model_repo_or_base": "__KT_LOCAL_TEST_BACKEND__",
                "adapter_hf_repo": "",
                "adapter_path": "",
                "adapter_sha256_optional": "",
                "enabled": True,
                "prompt_template_id": "raw",
                "scoring_method": "contains_expected_label",
                "max_new_tokens": 8,
            },
            {
                "arm_id": "A3_math_act_reasoning_preserving_compact",
                "model_repo_or_base": "__KT_LOCAL_TEST_BACKEND__",
                "adapter_hf_repo": "dummy",
                "adapter_path": "",
                "adapter_sha256_optional": "",
                "enabled": True,
                "prompt_template_id": "math_act_reasoning_preserving_compact",
                "compact_mode": "NUMERIC_BOUNDED_SCRATCH_THEN_FINAL",
                "scoring_method": "contains_expected_label",
                "max_new_tokens": 8,
            },
        ],
    }


def test_gsm8k_uses_bounded_scratch_and_mcq_answer_only() -> None:
    core = _core()
    assert core.compact_mode_for_row(_math_row(), {"arm_id": "A3_math_act_reasoning_preserving_compact"}) == "NUMERIC_BOUNDED_SCRATCH_THEN_FINAL"
    assert core.compact_mode_for_row(_mc_row(), {"arm_id": "A1_base_raw_finalizer_only"}) == "MCQ_ANSWER_ONLY"


def test_final_visible_answer_used_for_scoring_not_early_number() -> None:
    core = _core()
    row = _math_row()
    output = "Scratch: first try 4, then recompute 2 * 3.\nFinal: 6"
    visible = core.final_visible_answer(output, core.parse_answer(output), row)
    assert visible == "6"
    score, correct = core.score_output(visible, visible, row, "contains_expected_label")
    assert score == 1.0
    assert correct is True


def test_dualfront_runtime_emits_required_ledgers(tmp_path, monkeypatch) -> None:
    core = _core()
    runtime_root = tmp_path / "runtime"
    inputs = runtime_root / "runtime_inputs"
    inputs.mkdir(parents=True)
    manifest = {"schema_id": "kt.v17_7_4.realbench_row_manifest.v1", "row_count": 2, "rows": [_mc_row(), _math_row()]}
    (inputs / "truegen_row_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (inputs / "arm_model_config.json").write_text(json.dumps(_config(core)), encoding="utf-8")
    monkeypatch.setenv("KT_TRUEGEN_ALLOW_TEST_BACKEND", "1")
    monkeypatch.setenv("KT_COMPACT_ANSWER_CONTRACT", "1")
    monkeypatch.setenv("KT_REASONING_PRESERVING_COMPACT", "1")
    monkeypatch.setenv("KT_TRUEGEN_TARGET_ROWS", "2")
    monkeypatch.setenv("KT_OUTPUT_DIR", str(tmp_path / "out"))

    summary = core.run_truegen_runtime(runtime_root)

    assert summary["status"] == "PASS"
    for name in [
        "dual_frontier_scorecard.json",
        "visible_answer_ledger.json",
        "reasoning_preserving_compact_receipt.json",
        "visible_answer_scoring_receipt.json",
        "compact_accuracy_regression_gate.json",
        "route_margin_scorecard.json",
    ]:
        assert (tmp_path / "out" / name).exists()
    rows = core.read_jsonl(tmp_path / "out" / "truegen_arm_result_matrix.jsonl")
    assert all("reasoning_tokens" in row for row in rows)
    assert all(row["final_visible_answer_used_for_scoring"] is True for row in rows)


def test_dualfront_packet_contract_if_generated() -> None:
    packet = ROOT / "packets" / "ktv1774_dualfront_v1.zip"
    if not packet.exists():
        return
    with zipfile.ZipFile(packet) as archive:
        names = set(archive.namelist())
        assert "runtime_inputs/reasoning_preserving_compact_contract.json" in names
        manifest = json.loads(archive.read("run_manifest.json"))
        config = json.loads(archive.read("runtime_inputs/arm_model_config.json"))
        core = archive.read("KT_V1774_TRUEGEN_ARM_CORE.py").decode("utf-8")
    assert manifest["run_mode"] == "RUN_KTV1774_DUALFRONT_50"
    assert manifest["oracle_shadow_not_runtime"] is True
    assert config["reasoning_preserving_compact"] is True
    assert "A7_oracle_shadow_not_runtime" in config["required_arm_ids"]
    assert "dual_frontier_scorecard.json" in core


def test_13_lobe_targets_not_gates() -> None:
    registry = json.loads((ROOT / "adaptive" / "cognitive_lobe_registry.json").read_text(encoding="utf-8"))
    entries = registry.get("lobes") or registry.get("entries") or registry
    lobe_ids = set(entries if isinstance(entries, dict) else row["lobe_id"] for row in entries)
    assert len(lobe_ids) == 13
    assert "truth_engine" not in lobe_ids
    assert "claim_compiler" not in lobe_ids
    assert "router_control" not in lobe_ids
