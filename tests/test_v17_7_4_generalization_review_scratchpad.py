import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str):
    return json.loads((ROOT / path).read_text(encoding="utf-8-sig"))


def read_jsonl(path: str):
    return [json.loads(line) for line in (ROOT / path).read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def test_generalization_court_minimum_not_broad_claim():
    court = read_json("reports/v17_7_4_reprolock_generalization_court.json")
    claim = read_json("reports/v17_7_4_generalization_claim_boundary_receipt.json")
    score = read_json("reports/v17_7_4_generalization_probe_scorecard_binding.json")
    assert court["status"] == "GENERALIZATION_MINIMUM_SUPPORTED"
    assert court["secondary_status"] == "GSM8K_BOUNDARY_WEAKNESS_DETECTED"
    assert court["broad_generalization_claim"] is False
    assert court["compression_recovery_claim"] is False
    assert claim["broad_generalization_claim"] is False
    assert claim["promotion_authority"] is False
    assert score["correct"] == 39
    assert score["total"] == 50
    assert score["by_dataset"]["gsm8k"] == {"accuracy": 0.45, "correct": 9, "total": 20}
    assert score["by_dataset"]["arc_challenge"] == {"accuracy": 1.0, "correct": 15, "total": 15}
    assert score["by_dataset"]["hellaswag"] == {"accuracy": 1.0, "correct": 15, "total": 15}


def test_gsm8k_autopsy_is_row_level_and_not_parser_only():
    wrong = read_jsonl("reports/v17_7_4_generalization_wrong_row_table.jsonl")
    autopsy = read_json("reports/v17_7_4_generalization_gsm8k_failure_autopsy.json")
    owner = read_json("reports/v17_7_4_generalization_parser_vs_reasoning_owner_matrix.json")
    assert len(wrong) == 11
    assert {row["dataset"] for row in wrong} == {"gsm8k"}
    assert all(row["training_justified"] is False for row in wrong)
    assert all(row["raw_output_hash"] for row in wrong)
    assert autopsy["all_wrong_rows_gsm8k"] is True
    assert owner["parser_owned"] == 0
    assert owner["scratchpad_plausible_rows"] >= 7
    assert owner["finalizer_only_repair_rejected"] is True


def test_frontiers_keep_visible_and_full_token_accounting_separate():
    frontier = read_json("reports/v17_7_4_post_generalization_staged_frontier_update.json")
    token = read_json("reports/v17_7_4_post_generalization_token_accounting_frontier.json")
    assert frontier["verified_intelligence_frontier"]["heldout_generalization_probe"] == "39/50"
    assert frontier["gsm8k_math_frontier"]["generalization"] == "9/20"
    assert frontier["full_system_compression_frontier"]["status"] == "FULL_SYSTEM_COMPRESSION_NOT_RECOVERED"
    assert frontier["collapse_frontiers_forbidden"] is True
    assert token["visible_tpc_is_not_full_tpc"] is True
    assert token["scratchpad_tokens_must_count_in_full_tpc"] is True
    assert token["full_tpc"] > token["visible_tpc"]


def test_scratchpad_contract_is_math_only_audit_visible_and_not_global_runtime():
    design = read_json("reports/v17_7_4_math_ephemeral_scratchpad_design.json")
    ledger = read_json("reports/v17_7_4_math_scratchpad_token_ledger_contract.json")
    authority = read_json("reports/v17_7_4_math_scratchpad_runtime_authority_receipt.json")
    assert design["scope"] == "GSM8K_MATH_ONLY"
    assert design["global_runtime_authority"] is False
    assert design["scratchpad_tokens_count_in_full_tpc"] is True
    assert design["audit_visible"] is True
    assert design["arc_hellaswag_static_hold"] is True
    assert design["kt_hat_contamination_allowed"] is False
    assert design["router_changes_allowed"] is False
    assert design["finalizer_v2_allowed"] is False
    assert ledger["scratchpad_tokens_hidden_from_full_tpc"] is False
    assert "scratchpad_reasoning_tokens" in ledger["required_fields"]
    assert authority["microfurnace_runtime_authority"] is True
    assert authority["global_runtime_authority"] is False
    assert authority["promotion_authority"] is False


def test_epc_selects_microfurnace_without_training_or_promotion():
    epc = read_json("reports/v17_7_4_epc_decision_after_generalization_probe.json")
    next_lane = read_json("reports/v17_7_4_epc_next_evidence_lane_after_generalization.json")
    holding = read_json("reports/v17_7_4_multi_teacher_substrate_tournament_holding_register.json")
    assert epc["selected_next_lane"] == "RUN_MATH_SCRATCHPAD_MICROFURNACE_25"
    assert epc["adapter_training_authorized"] is False
    assert epc["router_training_authorized"] is False
    assert epc["promotion_authority"] is False
    assert epc["v18_runtime_authority"] is False
    assert next_lane["next_lawful_move"] == "RUN_KTV1774_MATH_SCRATCHPAD_MICROFURNACE_PACKET"
    assert holding["concept_status"] == "FUTURE_AFTER_GENERALIZATION_AND_SCRATCHPAD_EVIDENCE"
    assert holding["no_training_authority"] is True


def test_microfurnace_packet_is_gsm8k_only_and_contains_required_runtime_contracts():
    summary = read_json("reports/v17_7_4_generalization_review_scratchpad_builder_summary.json")
    preflight = read_json("reports/v17_7_4_math_scratchpad_microfurnace_preflight.json")
    manifest = read_json("admission/v17_7_4_math_scratchpad_microfurnace_row_manifest.json")
    packet = ROOT / summary["packet_path_if_any"]
    assert packet.exists()
    assert preflight["packet_sha256"] == summary["packet_sha256_if_any"]
    assert preflight["row_count"] == 25
    assert preflight["dataset_mix"] == {"gsm8k": 25}
    assert manifest["row_count"] == 25
    assert manifest["dataset_mix"] == {"gsm8k": 25}
    assert {row["dataset"] for row in manifest["rows"]} == {"gsm8k"}
    assert sum(1 for row in manifest["rows"] if row["scratchpad_microfurnace_role"] == "FAILED_HELDOUT_GSM8K_ROW") == 11
    with zipfile.ZipFile(packet) as archive:
        names = set(archive.namelist())
        assert "KTV1774_MATH_SCRATCHPAD_MICROFURNACE_RUNNER.py" in names
        assert "KT_V1774_TRUEGEN_ARM_CORE.py" in names
        assert "runtime_inputs/truegen_row_manifest.json" in names
        assert "runtime_inputs/arm_model_config.json" in names
        runner_source = archive.read("KTV1774_MATH_SCRATCHPAD_MICROFURNACE_RUNNER.py").decode("utf-8")
        config = json.loads(archive.read("runtime_inputs/arm_model_config.json"))
        packet_manifest = json.loads(archive.read("runtime_inputs/truegen_row_manifest.json"))
    for expected_alias in [
        "mathscratchpadtelemetry.json",
        "microfurnacescorecard.json",
        "opesupport_update.json",
    ]:
        assert expected_alias in runner_source
    assert config["compact_answer_contract"] is True
    assert config["reasoning_preserving_compact"] is True
    assert config["kt_hat_contamination_allowed"] is False
    assert config["route_admission_changes_allowed"] is False
    assert config["no_training"] is True
    assert config["no_promotion"] is True
    assert config["no_v18"] is True
    assert [arm["scratchpad_budget_tokens"] for arm in config["arms"]] == [0, 64, 96, 128]
    assert packet_manifest["dataset_mix"] == {"gsm8k": 25}
