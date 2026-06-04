from __future__ import annotations

import importlib.util
import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _core():
    path = ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py"
    spec = importlib.util.spec_from_file_location("kt_v1774_truegen_core_compact", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


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
        "measurement_mode": "REAL_BENCHMARK_GAUGE",
        "compact_answer_contract": True,
        "stream_rows_to_disk": True,
        "arms": [
            {
                "arm_id": arm,
                "model_repo_or_base": "__KT_LOCAL_TEST_BACKEND__",
                "adapter_hf_repo": "",
                "adapter_path": "",
                "adapter_sha256_optional": "",
                "enabled": True,
                "prompt_template_id": "raw",
                "scoring_method": "multiple_choice_letter",
                "max_new_tokens": 8,
            }
            for arm in core.ARM_IDS
        ],
    }


def _row(index: int = 0) -> dict:
    return {
        "schema_id": "kt.v17_7_4.truegen_row.v1",
        "sample_id": f"compact:{index}",
        "dataset": "unit_mc",
        "split": "test",
        "task_family": "science_reasoning",
        "benchmark_source": "REAL_BENCHMARK_ROW",
        "question_text": "Which option is correct?\nA. Alpha\nB. Beta\nC. Gamma\nD. Delta",
        "expected_answer": "C",
        "expected_label_or_oracle_label": "C",
        "answer_type": "multiple_choice_letter",
        "answer_format_contract": "Emit only the option letter.",
        "prompt": "Which option is correct?\nA. Alpha\nB. Beta\nC. Gamma\nD. Delta",
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


def test_final_visible_answer_strips_multiple_choice_to_letter() -> None:
    core = _core()
    row = _row()
    visible = core.final_visible_answer("Final: C because gamma is correct", "C because gamma is correct", row)
    assert visible == "C"
    assert core.count_tokens(visible) == 1


def test_compact_runtime_emits_token_ledger_and_oracle_table(tmp_path, monkeypatch) -> None:
    core = _core()
    runtime_root = tmp_path / "runtime"
    inputs = runtime_root / "runtime_inputs"
    inputs.mkdir(parents=True)
    manifest = {"schema_id": "kt.v17_7_4.realbench_row_manifest.v1", "row_count": 2, "rows": [_row(0), _row(1)]}
    (inputs / "truegen_row_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (inputs / "arm_model_config.json").write_text(json.dumps(_config(core)), encoding="utf-8")
    monkeypatch.setenv("KT_TRUEGEN_ALLOW_TEST_BACKEND", "1")
    monkeypatch.setenv("KT_COMPACT_ANSWER_CONTRACT", "1")
    monkeypatch.setenv("KT_TRUEGEN_TARGET_ROWS", "2")
    monkeypatch.setenv("KT_OUTPUT_DIR", str(tmp_path / "out"))

    summary = core.run_truegen_runtime(runtime_root)

    assert summary["status"] == "PASS"
    assert (tmp_path / "out" / "token_accounting_ledger.json").exists()
    assert (tmp_path / "out" / "compact_answer_contract_receipt.json").exists()
    assert (tmp_path / "out" / "answer_only_finalizer_receipt.json").exists()
    assert (tmp_path / "out" / "oracle_route_table.jsonl").exists()
    assert (tmp_path / "out" / "specialist_admission_atlas.json").exists()
    ledger = json.loads((tmp_path / "out" / "token_accounting_ledger.json").read_text(encoding="utf-8"))
    assert "visible_answer_tokens_per_correct" in ledger["accounting_modes"]
    rows = core.read_jsonl(tmp_path / "out" / "truegen_arm_result_matrix.jsonl")
    assert all("visible_answer_tokens" in row for row in rows)


def test_compact_packet_contains_contract_and_runtime_outputs() -> None:
    packet = ROOT / "packets" / "ktv1774_realbench_compact_v1.zip"
    assert packet.exists()
    with zipfile.ZipFile(packet) as archive:
        names = set(archive.namelist())
        assert "runtime_inputs/compact_answer_contract.json" in names
        manifest = json.loads(archive.read("run_manifest.json"))
        core = archive.read("KT_V1774_TRUEGEN_ARM_CORE.py").decode("utf-8")
    assert manifest["compact_answer_contract"] is True
    assert manifest["token_accounting_ledger_required"] is True
    assert "token_accounting_ledger.json" in core
    assert "visible_answer_tokens_per_correct" in core


def test_specialist_admission_atlas_is_candidate_only() -> None:
    atlas = json.loads((ROOT / "reports" / "v17_7_4_specialist_admission_atlas.json").read_text(encoding="utf-8"))
    assert atlas["status"] == "PASS_CANDIDATE_ONLY"
    assert atlas["promotion_authority"] is False
    assert atlas["router_superiority_claim"] is False
    assert atlas["best_current_candidate_arm"] == "math_act_adapter_global"


def test_g2_sentinel_status_remains_blocked_without_exact_prompts() -> None:
    status = json.loads((ROOT / "reports" / "g2_sentinel_source_status.json").read_text(encoding="utf-8"))
    assert status["status"] == "BLOCKED"
    assert status["outcome"] == "KT_BLOCKED__G2_SENTINEL_SOURCE_MISSING"
