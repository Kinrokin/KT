from __future__ import annotations

import json
import zipfile
from pathlib import Path

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core
from scripts import build_v17_7_4_oracle_academy_reentry_packet as builder


ROOT = Path(__file__).resolve().parents[1]


def test_known_good_reproduction_arm_is_raw_scored_and_adapter_equivalent() -> None:
    config = builder.oracle_academy_config()
    arms = {arm["arm_id"]: arm for arm in config["arms"]}
    source = json.loads((ROOT / "configs/v17_7_4/arm_model_config.json").read_text(encoding="utf-8"))["arms"]
    math_act = {arm["arm_id"]: arm for arm in source}["math_act_adapter_global"]
    known = arms["A_known_good_math_act_reproduction"]

    assert known["adapter_hf_repo"] == math_act["adapter_hf_repo"]
    assert known["adapter_hf_subfolder"] == math_act["adapter_hf_subfolder"]
    assert known["adapter_sha256_optional"] == math_act["adapter_sha256_optional"]
    assert known["prompt_template_id"] == math_act["prompt_template_id"]
    assert known["max_new_tokens"] == math_act["max_new_tokens"]
    assert known["score_from_visible_answer"] is False
    assert known["compact_scoring_disabled"] is True
    assert core.compact_scoring_enabled(config, known) is False


def test_oracle_academy_config_separates_reproduction_finalizer_compact_and_admission() -> None:
    config = builder.oracle_academy_config()
    required = config["required_arm_ids"]
    assert required == [
        "A0_base_raw",
        "A1_prior_realbench_base_raw_reproduction",
        "A_known_good_math_act_reproduction",
        "A3_prior_math_act_plus_finalizer_only",
        "A4_math_act_reasoning_preserving_compact_v2",
        "A5_kt_hat_risk_gated_v2",
        "A6_specialist_admission_candidate_v2",
        "A7_oracle_shadow",
    ]
    assert config["measurement_mode"] == "ORACLE_AUTOPSY_ACADEMY_REENTRY"
    assert config["oracle_correctness_used_as_runtime_feature"] is False
    assert config["adapter_training_authorized"] is False
    assert config["router_training_authorized"] is False
    assert config["promotion_authority"] is False
    assert config["v18_runtime_authority"] is False
    assert core.validate_arm_model_config(config) == []


def test_assessment_bundle_includes_oracle_academy_runtime_artifacts() -> None:
    required = {
        "known_good_lobe_reproduction_receipt.json",
        "realbench_vs_dualfront_arm_diff_receipt.json",
        "gsm8k_regression_autopsy.json",
        "parser_failure_repair_plan.json",
        "oracle_autopsy_table.jsonl",
        "scar_delta_registry.json",
        "recursive_learning_delta_manifest.json",
        "academy_repair_plan.json",
        "lobe_tournament_reentry_plan.json",
        "tie_merge_child_lobe_plan.json",
        "kt_hat_mount_comparison_plan.json",
        "claim_ceiling_receipt.json",
    }
    assert required.issubset(set(core.ASSESSMENT_FILES))


def test_runtime_autopsy_functions_emit_owner_and_repair_surfaces() -> None:
    rows = [
        {
            "sample_id": "s1",
            "dataset": "GSM8K",
            "task_family": "formal_math",
            "arm_id": "A0_base_raw",
            "score": 0.0,
            "correct": False,
            "total_tokens": 10,
            "latency_ms": 1,
            "parser_format_failure": False,
        },
        {
            "sample_id": "s1",
            "dataset": "GSM8K",
            "task_family": "formal_math",
            "arm_id": "A_known_good_math_act_reproduction",
            "score": 1.0,
            "correct": True,
            "total_tokens": 20,
            "latency_ms": 1,
            "parser_format_failure": False,
        },
        {
            "sample_id": "s1",
            "dataset": "GSM8K",
            "task_family": "formal_math",
            "arm_id": "A6_specialist_admission_candidate_v2",
            "score": 0.0,
            "correct": False,
            "total_tokens": 30,
            "latency_ms": 1,
            "parser_format_failure": False,
        },
    ]
    autopsy = core.build_oracle_autopsy_rows(rows)
    assert autopsy[0]["oracle_choice"] == "A_known_good_math_act_reproduction"
    assert autopsy[0]["failure_owner"] == "ROUTE_OWNED"
    scar = core.build_scar_delta_registry(autopsy)
    delta = core.recursive_learning_delta_manifest(scar)
    academy = core.academy_repair_plan(scar, {"status": "PASS"})
    assert scar["scar_count"] == 1
    assert delta["delta_rows"][0]["repair_owner"] == "ROUTE_OWNED"
    assert "ROUTE_OWNED" in academy["next_repair_surfaces"]


def test_oracle_academy_packet_contract_if_generated() -> None:
    packet = ROOT / "packets/ktv1774_oracle_academy_reentry_v1.zip"
    if not packet.exists():
        return
    with zipfile.ZipFile(packet) as archive:
        names = set(archive.namelist())
        manifest = json.loads(archive.read("run_manifest.json").decode("utf-8"))
        config = json.loads(archive.read("runtime_inputs/arm_model_config.json").decode("utf-8"))
    assert "KT_V1774_TRUEGEN_ARM_CORE.py" in names
    assert "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py" in names
    assert manifest["run_mode"] == "RUN_KTV1774_ORACLE_ACADEMY_REENTRY_50"
    assert manifest["known_good_reproduction_required"] is True
    assert manifest["oracle_autopsy_table_required"] is True
    assert manifest["no_training"] is True
    assert manifest["no_promotion"] is True
    assert manifest["no_v18"] is True
    assert config["measurement_mode"] == "ORACLE_AUTOPSY_ACADEMY_REENTRY"
    assert "A_known_good_math_act_reproduction" in config["required_arm_ids"]
