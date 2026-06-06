from __future__ import annotations

import json
import zipfile
from pathlib import Path

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core
from scripts import build_v17_7_4_dual_frontier_repair_packet as builder


ROOT = Path(__file__).resolve().parents[1]


def test_dual_frontier_repair_config_preserves_byte_locked_control() -> None:
    config = builder.dual_frontier_repair_config()
    arms = {arm["arm_id"]: arm for arm in config["arms"]}

    assert config["measurement_mode"] == core.DUAL_FRONTIER_REPAIR_MODE
    assert config["known_good_reproduction_required"] is True
    assert config["oracle_correctness_used_as_runtime_feature"] is False
    assert config["adapter_training_authorized"] is False
    assert config["router_training_authorized"] is False
    assert config["promotion_authority"] is False
    assert config["v18_runtime_authority"] is False
    assert core.REPROLOCK_ARM_ID in config["required_arm_ids"]
    assert arms[core.REPROLOCK_ARM_ID]["reproduction_mode"] == core.TRUE_KNOWN_GOOD_BYTE_REPRO
    assert arms[core.REPROLOCK_ARM_ID]["score_from_visible_answer"] is False
    assert arms["A2_known_good_parser_scorer_repair"]["reproduction_mode"] == core.TRUE_KNOWN_GOOD_BYTE_REPRO
    assert arms["A3_known_good_finalizer_extraction_repair"]["reproduction_mode"] == core.TRUE_KNOWN_GOOD_BYTE_REPRO
    assert core.validate_arm_model_config(config) == []


def test_route_specific_compression_policy_is_teacher_only() -> None:
    rows = [
        {"sample_id": "s1", "dataset": "GSM8K", "task_family": "formal_math", "arm_id": "A0_base_raw", "correct": False, "score": 0.0, "total_tokens": 20, "latency_ms": 1},
        {"sample_id": "s1", "dataset": "GSM8K", "task_family": "formal_math", "arm_id": core.REPROLOCK_ARM_ID, "correct": True, "score": 1.0, "total_tokens": 100, "latency_ms": 1},
        {"sample_id": "s1", "dataset": "GSM8K", "task_family": "formal_math", "arm_id": "A4_oracle_derived_route_specific_compression_candidate", "correct": True, "score": 1.0, "total_tokens": 40, "latency_ms": 1},
    ]
    scorecards = {
        "token_efficiency": {"matrix": {core.REPROLOCK_ARM_ID: {"correct": 1, "tokens_per_correct": 100}}},
        "token_accounting_ledger": {"matrix": {core.REPROLOCK_ARM_ID: {"full_prompt_plus_output_tokens_per_correct": 100, "visible_answer_tokens_per_correct": 1}}},
    }
    policy, table, regret = core.route_specific_compression_policy(rows, scorecards)

    assert policy["status"] == "PASS_CANDIDATE_ONLY"
    assert policy["runtime_authority"] is False
    assert policy["oracle_correctness_used_as_runtime_feature"] is False
    assert policy["candidate_improves_full_tokens"] is True
    assert table[0]["runtime_admissible"] is False
    assert regret[0]["promotion_authority"] is False


def test_dual_frontier_repair_runtime_emits_repair_receipts(tmp_path, monkeypatch) -> None:
    config = {
        "base_model_repo": "__KT_LOCAL_TEST_BACKEND__",
        "load_in_4bit": False,
        "torch_dtype": "auto",
        "max_new_tokens": 8,
        "batch_size": 1,
        "device_map": "cpu",
        "generation_seed": 7,
        "row_limit": 39,
        "measurement_mode": core.DUAL_FRONTIER_REPAIR_MODE,
        "compact_answer_contract": True,
        "reasoning_preserving_compact": True,
        "stream_rows_to_disk": True,
        "required_arm_ids": ["A0_base_raw", core.REPROLOCK_ARM_ID],
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
                "arm_id": core.REPROLOCK_ARM_ID,
                "model_repo_or_base": "__KT_LOCAL_TEST_BACKEND__",
                "adapter_hf_repo": "dummy",
                "adapter_path": "",
                "adapter_sha256_optional": "",
                "enabled": True,
                "prompt_template_id": "math_act",
                "scoring_method": "contains_expected_label",
                "max_new_tokens": 8,
                "reproduction_mode": core.TRUE_KNOWN_GOOD_BYTE_REPRO,
            },
        ],
    }
    row = {
        "schema_id": "kt.v17_7_4.truegen_row.v1",
        "sample_id": "repair:gsm8k:0",
        "dataset": "GSM8K",
        "split": "test",
        "task_family": "formal_math",
        "benchmark_source": "REAL_BENCHMARK_ROW",
        "question_text": "What is 2 + 2?",
        "expected_answer": "4",
        "expected_label_or_oracle_label": "4",
        "answer_type": "numeric_final_answer",
        "answer_format_contract": "Emit only the normalized number.",
        "prompt": "x",
        "prompt_hash": "x",
        "label_source": "PUBLIC_BENCHMARK_GROUND_TRUTH",
        "scoring_rule": "contains_expected_label",
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
    runtime_root = tmp_path / "runtime"
    inputs = runtime_root / "runtime_inputs"
    inputs.mkdir(parents=True)
    rows = []
    for index in range(39):
        item = dict(row)
        item["sample_id"] = f"repair:gsm8k:{index}"
        rows.append(item)
    (inputs / "truegen_row_manifest.json").write_text(json.dumps({"schema_id": "x", "row_count": 39, "rows": rows}), encoding="utf-8")
    (inputs / "arm_model_config.json").write_text(json.dumps(config), encoding="utf-8")
    monkeypatch.setenv("KT_TRUEGEN_ALLOW_TEST_BACKEND", "1")
    monkeypatch.setenv("KT_TRUEGEN_TARGET_ROWS", "39")
    monkeypatch.setenv("KT_OUTPUT_DIR", str(tmp_path / "out"))

    summary = core.run_truegen_runtime(runtime_root)

    assert summary["status"] == "PASS"
    assert summary["outcome"] == builder.OUTCOME
    for name in [
        "v17_7_4_dual_frontier_repair_scorecard.json",
        "v17_7_4_route_specific_compression_candidate.json",
        "v17_7_4_parser_scorer_repair_authority_receipt.json",
        "v17_7_4_finalizer_extraction_repair_plan.json",
        "v17_7_4_fep_router_shadow_receipt.json",
        "v17_7_4_memory_authority_decay_receipt.json",
        "v17_7_4_gt_fep_pruning_shadow_receipt.json",
        "v17_7_4_agent_diff_contract_receipt.json",
    ]:
        assert (tmp_path / "out" / name).exists()


def test_dual_frontier_repair_packet_contract_if_generated() -> None:
    packet = ROOT / "packets" / builder.PACKET_NAME
    if not packet.exists():
        return
    with zipfile.ZipFile(packet) as archive:
        manifest = json.loads(archive.read("run_manifest.json").decode("utf-8"))
        config = json.loads(archive.read("runtime_inputs/arm_model_config.json").decode("utf-8"))
        names = set(archive.namelist())

    assert manifest["run_mode"] == builder.RUN_MODE
    assert manifest["measurement_mode"] == core.DUAL_FRONTIER_REPAIR_MODE
    assert manifest["no_training"] is True
    assert manifest["no_promotion"] is True
    assert manifest["no_v18"] is True
    assert core.REPROLOCK_ARM_ID in config["required_arm_ids"]
    assert "runtime_inputs/prior_realbench_math_act_prompt_manifest.jsonl" in names
