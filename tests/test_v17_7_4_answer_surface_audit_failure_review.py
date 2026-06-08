from __future__ import annotations

import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8-sig"))


def read_jsonl(path: str) -> list[dict]:
    return [json.loads(line) for line in (ROOT / path).read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def test_answer_surface_failure_review_binds_negative_audit_and_preserves_claim_ceiling() -> None:
    summary = read_json("reports/v17_7_4_answer_surface_audit_failure_review_builder_summary.json")
    binding = read_json("reports/v17_7_4_answer_surface_audit_no_runtime_binding.json")
    claim = read_json("reports/v17_7_4_answer_surface_audit_claim_boundary_receipt.json")

    assert summary["status"] == "PASS"
    assert summary["claim_ceiling_status"] == "PRESERVED"
    assert binding["parser_canonicalizer_runtime_authority"] is False
    assert binding["parser_microfurnace_packet_generated"] is False
    assert claim["status"] == "PASS"
    assert claim["commercial_claim"] is False
    assert claim["router_superiority_claim"] is False
    assert claim["g2_recovered_claim"] is False


def test_noop_invariant_preserves_control_correct_rows() -> None:
    receipt = read_json("reports/v17_7_4_answer_surface_audit_noop_invariant_receipt.json")
    rows = read_jsonl("reports/v17_7_4_parser_canonicalizer_noop_baseline_table.jsonl")

    assert receipt["status"] == "PASS"
    assert receipt["control_correct_preservation_rate"] == 1.0
    assert receipt["damage_to_control_correct"] == 0
    assert receipt["parser_net_accuracy_delta"] == 0
    assert rows
    assert all(row["current_scorer_preserved"] is True for row in rows)
    assert all(row["canonicalizer_disabled"] is True for row in rows)
    assert all(row["would_damage_control_correct"] is False for row in rows)


def test_damage_root_cause_and_rules_are_quarantined() -> None:
    root = read_json("reports/v17_7_4_answer_surface_audit_damage_root_cause.json")
    matrix = read_json("reports/v17_7_4_parser_rule_damage_matrix.json")
    quarantine = read_json("reports/v17_7_4_parser_canonicalizer_runtime_quarantine_receipt.json")
    no_authority = read_json("reports/v17_7_4_parser_canonicalizer_no_runtime_authority_receipt.json")

    assert root["status"] == "VALID_NEGATIVE_AUDIT_WITH_SCORER_SURFACE_BINDING_DEFECT"
    assert root["damaged_control_correct_rows"] > 0
    assert root["parser_runtime_repair_earned"] is False
    assert matrix["parser_canonicalizer_runtime_authority"] is False
    assert any(rule["damage"] > 0 for rule in matrix["rules"])
    assert quarantine["parser_canonicalizer_runtime_authority"] is False
    assert no_authority["parser_repair_packet_allowed"] is False


def test_expected_answer_and_row_source_audits_pass() -> None:
    leakage = read_json("reports/v17_7_4_parser_audit_expected_answer_leakage_review.json")
    alignment = read_json("reports/v17_7_4_parser_audit_row_source_alignment_receipt.json")
    hash_only = read_json("reports/v17_7_4_parser_audit_expected_answer_hash_only_receipt.json")

    assert leakage["status"] == "PASS"
    assert leakage["expected_answer_values_used_for_candidate_selection"] is False
    assert leakage["expected_answer_values_used_for_canonicalization"] is False
    assert alignment["status"] == "PASS"
    assert hash_only["candidate_selection_gold_blind"] is True


def test_control_only_gsm8k_extension_source_is_bound_nonoverlapping_and_hash_only() -> None:
    binding = read_json("reports/v17_7_4_control_only_gsm8k_extension_row_source_binding.json")
    nonoverlap = read_json("reports/v17_7_4_control_only_gsm8k_extension_nonoverlap_receipt.json")
    manifest = read_json("admission/v17_7_4_control_only_gsm8k_extension_row_manifest.json")
    prompt_rows = read_jsonl("admission/v17_7_4_control_only_gsm8k_extension_math_act_prompt_manifest.jsonl")

    assert binding["status"] == "BOUND"
    assert binding["row_count"] == 100
    assert binding["dataset_mix"] == {"gsm8k": 100}
    assert binding["expected_answer_model_visible"] is False
    assert nonoverlap["status"] == "PASS"
    assert manifest["row_count"] == 100
    assert manifest["dataset_mix"] == {"gsm8k": 100}
    assert all(row["expected_answer_visible_to_model"] is False for row in manifest["rows"])
    assert len(prompt_rows) == 100
    assert all(row["expected_answer_model_visible"] is False for row in prompt_rows)
    assert all(row["expected_answer_used_for_candidate_selection"] is False for row in prompt_rows)


def test_epc_allows_only_control_extension_packet_when_gates_pass() -> None:
    epc = read_json("reports/v17_7_4_epc_decision_after_answer_surface_audit_failure.json")
    gate = read_json("reports/v17_7_4_next_kaggle_gate_after_parser_audit_failure.json")
    summary = read_json("reports/v17_7_4_answer_surface_audit_failure_review_builder_summary.json")

    assert epc["selected_next_lane"] == "RUN_CONTROL_ONLY_GSM8K_EXTENSION_100"
    assert epc["parser_runtime_authority"] is False
    assert gate["status"] == "PASS_RUNTIME_PACKET_READY"
    assert gate["packet_path_if_any"] == "packets/ktv1774_control_only_gsm8k_extension_v1.zip"
    assert summary["selected_next_lane"] == "RUN_CONTROL_ONLY_GSM8K_EXTENSION_100"
    assert summary["blockers"] == []


def test_control_only_packet_contains_no_parser_scratchpad_hat_or_route_mutation() -> None:
    packet = ROOT / "packets" / "ktv1774_control_only_gsm8k_extension_v1.zip"
    assert packet.exists()
    with zipfile.ZipFile(packet) as archive:
        names = set(archive.namelist())
        run_manifest = json.loads(archive.read("run_manifest.json").decode("utf-8"))
        row_manifest = json.loads(archive.read("runtime_inputs/truegen_row_manifest.json").decode("utf-8"))
        config = json.loads(archive.read("runtime_inputs/arm_model_config.json").decode("utf-8"))

    assert "KTV1774_CONTROL_ONLY_GSM8K_EXTENSION_RUNNER.py" in names
    assert run_manifest["run_mode"] == "RUN_KTV1774_CONTROL_ONLY_GSM8K_EXTENSION_100"
    assert run_manifest["parser_canonicalizer_runtime"] is False
    assert run_manifest["scratchpad_runtime"] is False
    assert run_manifest["kt_hat_runtime"] is False
    assert run_manifest["route_admission_changes"] is False
    assert row_manifest["row_count"] == 100
    assert row_manifest["dataset_mix"] == {"gsm8k": 100}
    assert config["parser_canonicalizer_runtime_allowed"] is False
    assert config["scratchpad_runtime_allowed"] is False
    assert config["kt_hat_runtime_allowed"] is False
    assert config["route_admission_changes_allowed"] is False
    assert config["no_training"] is True
    assert config["no_promotion"] is True
    assert config["no_v18"] is True
