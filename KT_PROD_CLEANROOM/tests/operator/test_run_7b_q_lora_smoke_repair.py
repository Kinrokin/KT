from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tools.operator import run_7b_q_lora_smoke_repair as lane


def _copy_inputs(tmp_path: Path) -> None:
    root = lane.repo_root()
    for raw in sorted(lane.INPUTS.values()):
        source = root / raw
        target = tmp_path / raw
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def test_7b_smoke_partial_assessment_emits_repair_next(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)

    summary = lane.run(output_root=tmp_path)

    assert summary["outcome"] == lane.PARTIAL_OUTCOME
    assert summary["next_lawful_move"] == "RUN_7B_Q_LORA_SMOKE_REPAIR"
    assert summary["clean_target_outcome_after_success"] == "KT_7B_Q_LORA_SMOKE_CLEAN_VALIDATED__TRANCHE_NEXT"
    assert summary["claim_ceiling"] == "unchanged"
    assert len(summary["blockers"]) == 3

    partial = _load(tmp_path / lane.OUTPUTS["partial_receipt"])
    assert partial["clean_smoke_pass"] is False
    assert partial["valid_as_runtime_smoke_attempt"] is True
    assert partial["valid_as_clean_current_head_proof"] is False
    assert partial["training_errors_count"] == 2
    assert partial["negative_result_count"] == 2
    assert partial["tranche_authorized"] is False
    assert partial["seven_b_amplification_proven"] is False


def test_repair_packet_has_t4_safe_oom_and_class_support_repairs(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)

    lane.run(output_root=tmp_path)
    packet = _load(tmp_path / lane.OUTPUTS["repair_packet"])
    settings = packet["repair_run_settings"]

    assert settings["KT_MAX_STEPS_COHORT"] == 1
    assert settings["KT_MAX_STEPS_PER_LOBE"] == 1
    assert settings["KT_MAX_STEPS_COHORT2"] == 1
    assert settings["KT_MAX_SEQ_LEN"] == 96
    assert settings["KT_BATCH_SIZE"] == 1
    assert settings["KT_GRAD_ACCUM"] == 32
    assert settings["KT_ROUTER_EVAL_MIN_PER_CLASS"] == 4
    assert "max_split_size_mb:64" in settings["PYTORCH_CUDA_ALLOC_CONF"]
    assert packet["memory_hygiene_policy"]["clear_gpu_between_adapter_trainings"] is True
    assert packet["clean_pass_required_conditions"]["training_errors_count"] == 0
    assert packet["clean_pass_required_conditions"]["negative_result_count"] == 0


def test_repair_packet_requires_real_qlora_not_silent_fallback(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)

    lane.run(output_root=tmp_path)
    packet = _load(tmp_path / lane.OUTPUTS["repair_packet"])

    assert packet["bitsandbytes_policy"]["install_before_model_load"] is True
    assert packet["bitsandbytes_policy"]["import_before_model_load"] is True
    assert packet["bitsandbytes_policy"]["fail_closed_if_unavailable"] is True
    assert packet["bitsandbytes_policy"]["fail_closed_if_4bit_modules_not_detected"] is True
    assert packet["bitsandbytes_policy"]["do_not_silently_fallback_to_full_precision_for_clean_qlora_smoke"] is True
    assert packet["clean_pass_required_conditions"]["qlora_effective"] is True


def test_repair_packet_preserves_current_head_binding_policy(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)

    lane.run(output_root=tmp_path)
    packet = _load(tmp_path / lane.OUTPUTS["repair_packet"])

    assert packet["head_binding_policy"]["fail_clean_current_head_proof_if_requested_head_unreachable"] is True
    assert "public main" in packet["head_binding_policy"]["fallback"]


def test_repair_next_move_supersedes_prior_clean_smoke_next_in_registry(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)

    lane.run(output_root=tmp_path)
    registry = _load(tmp_path / lane.INPUTS["registry"])

    old_next = [artifact for artifact in registry["artifacts"] if artifact["artifact_id"] == "NEXT_LAWFUL_MOVE"]
    assert old_next
    assert old_next[-1]["controls_execution"] is False
    assert old_next[-1]["authority_state"] == "SUPERSEDED"
    assert old_next[-1]["superseded_by"] == lane.OUTPUTS["repair_next_move"]

    repair_next = [
        artifact
        for artifact in registry["artifacts"]
        if artifact["artifact_id"] == "KT_7B_Q_LORA_SMOKE_REPAIR_NEXT_LAWFUL_MOVE"
    ]
    assert repair_next
    assert repair_next[-1]["controls_execution"] is True
    assert repair_next[-1]["role"] == "seven_b_smoke_next_move"


def test_repair_runbook_is_markdown_not_json(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)

    lane.run(output_root=tmp_path)
    runbook = (tmp_path / lane.OUTPUTS["repair_runbook"]).read_text(encoding="utf-8-sig")

    assert runbook.startswith("# KT 7B QLoRA Smoke Repair Runbook")
    assert "RUN_7B_Q_LORA_SMOKE_REPAIR" in runbook
    assert "torch.cuda.empty_cache" in runbook


def test_claim_ceiling_drift_blocks_repair_lane(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)
    claim_path = tmp_path / lane.INPUTS["claim_ceiling"]
    claim = _load(claim_path)
    claim["commercial_claim_authorized"] = True
    claim_path.write_text(json.dumps(claim, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="Claim ceiling drift"):
        lane.run(output_root=tmp_path)
