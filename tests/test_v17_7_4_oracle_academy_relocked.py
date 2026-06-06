from __future__ import annotations

import json
import zipfile
from pathlib import Path

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core
from scripts import build_v17_7_4_oracle_academy_relocked_packet as builder


ROOT = Path(__file__).resolve().parents[1]


def test_relocked_config_uses_byte_repro_control_without_claim_expansion() -> None:
    config = builder.relocked_config()
    arms = {arm["arm_id"]: arm for arm in config["arms"]}

    assert config["measurement_mode"] == core.ORACLE_ACADEMY_RELOCKED_MODE
    assert config["known_good_reproduction_required"] is True
    assert config["oracle_correctness_used_as_runtime_feature"] is False
    assert config["adapter_training_authorized"] is False
    assert config["router_training_authorized"] is False
    assert config["promotion_authority"] is False
    assert config["v18_runtime_authority"] is False
    assert core.REPROLOCK_ARM_ID in config["required_arm_ids"]
    assert arms[core.REPROLOCK_ARM_ID]["reproduction_mode"] == core.TRUE_KNOWN_GOOD_BYTE_REPRO
    assert arms[core.REPROLOCK_ARM_ID]["score_from_visible_answer"] is False
    assert arms["A2_true_known_good_math_act_finalizer_only"]["reproduction_mode"] == core.TRUE_KNOWN_GOOD_BYTE_REPRO
    assert arms["A2_true_known_good_math_act_finalizer_only"]["score_from_visible_answer"] is True
    assert core.validate_arm_model_config(config) == []


def test_oracle_autopsy_recognizes_reprolock_arm_as_stable_known_good_control() -> None:
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
            "arm_id": core.REPROLOCK_ARM_ID,
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
            "arm_id": "A5_specialist_admission_after_reprolock",
            "score": 0.0,
            "correct": False,
            "total_tokens": 30,
            "latency_ms": 1,
            "parser_format_failure": False,
        },
    ]
    autopsy = core.build_oracle_autopsy_rows(rows)
    assert autopsy[0]["oracle_choice"] == core.REPROLOCK_ARM_ID
    assert autopsy[0]["failure_owner"] == "ROUTE_OWNED"
    assert autopsy[0]["repair_bid"]["training_authorized"] is False


def test_reprolock_post_runtime_receipts_update_stage_and_ope_without_authority_expansion() -> None:
    known = {
        "status": "PASS",
        "observed_total": 50,
        "reproduction_arm_id": core.REPROLOCK_ARM_ID,
    }
    stage = core.post_runtime_reproduction_stage_ladder_receipt(known, 50)
    ope = core.ope_authority_after_reprolock_receipt(known)

    assert stage["stage0_static_identity_audit"] == "PASS"
    assert stage["stage1_five_row_probe"] == "SKIPPED_BY_FULL_STAGE2_WITH_RUNTIME_EVIDENCE"
    assert stage["stage2_fifty_row_reproduction"] == "PASS"
    assert ope["max_authority"] == "reproduction_lock_passed__ope_still_not_fresh_generation_authority"
    assert ope["training_authorized"] is False
    assert ope["promotion_authorized"] is False
    assert ope["router_superiority_authorized"] is False


def test_parser_finalizer_and_compression_are_classified_not_trained() -> None:
    scorecards = {
        "parser_error": {
            "matrix": {
                core.REPROLOCK_ARM_ID: {"parser_format_failure_rate": 0.54},
            }
        },
        "answer_format": {
            "matrix": {
                core.REPROLOCK_ARM_ID: {"answer_format_drift_rate": 0.66},
            }
        },
        "token_efficiency": {
            "matrix": {
                core.REPROLOCK_ARM_ID: {"tokens_per_correct": 145.12},
            }
        },
        "token_accounting_ledger": {
            "matrix": {
                core.REPROLOCK_ARM_ID: {
                    "full_prompt_plus_output_tokens_per_correct": 145.12,
                    "visible_answer_tokens_per_correct": 1.22,
                }
            }
        },
    }
    parser = core.parser_finalizer_repair_authority_receipt(scorecards)
    answer = core.answer_format_drift_repair_plan(scorecards)
    compression = core.post_reprolock_compression_gap_receipt(scorecards)

    assert parser["owner_classification"] == "SCORER_FINALIZER_OWNED"
    assert parser["adapter_training_authorized"] is False
    assert answer["training_authorized"] is False
    assert compression["status"] == "BLOCKED"
    assert compression["g2_recovered_claim"] is False


def test_relocked_packet_contract_if_generated() -> None:
    packet = ROOT / "packets" / builder.PACKET_NAME
    if not packet.exists():
        return
    with zipfile.ZipFile(packet) as archive:
        names = set(archive.namelist())
        manifest = json.loads(archive.read("run_manifest.json").decode("utf-8"))
        config = json.loads(archive.read("runtime_inputs/arm_model_config.json").decode("utf-8"))

    assert "runtime_inputs/prior_realbench_math_act_prompt_manifest.jsonl" in names
    assert "KT_V1774_TRUEGEN_ARM_CORE.py" in names
    assert manifest["run_mode"] == builder.RUN_MODE
    assert manifest["measurement_mode"] == core.ORACLE_ACADEMY_RELOCKED_MODE
    assert manifest["no_training"] is True
    assert manifest["no_promotion"] is True
    assert manifest["no_v18"] is True
    assert core.REPROLOCK_ARM_ID in config["required_arm_ids"]
