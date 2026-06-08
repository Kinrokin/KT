from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def run_builder() -> dict:
    completed = subprocess.run(
        [sys.executable, "scripts/build_v17_7_4_math_pretraining_hypothesis_court.py"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(completed.stdout)


def test_builder_returns_no_training_no_runtime_success() -> None:
    summary = run_builder()

    assert summary["outcome"] == (
        "KT_MATH_PRETRAINING_HYPOTHESIS_COURT_BOUND__TRAINING_AUTHORITY_STILL_FALSE__"
        "NEXT_LANE_DECIDED__CLAIM_CEILING_PRESERVED"
    )
    assert summary["pretraining_hypothesis_binding_status"] == "BOUND"
    assert summary["hypothesis_ledger_status"] == "PASS"
    assert summary["prompt_format_suppression_audit_status"] == "PROMPT_FORMAT_SUPPRESSION_PLAUSIBLE_UNTESTED"
    assert summary["prompt_format_probe_design_status"] == "DESIGN_ONLY"
    assert summary["parser_recoverability_correction_status"] == "PARSER_NOT_BOTTLENECK"
    assert summary["parser_plus_22_claim_block_status"] == "PASS_BLOCKED"
    assert summary["math_corpus_audit_status"] == "SOURCE_NOT_BOUND"
    assert summary["training_prerequisite_decision_status"] == "TRAINING_REQUEST_PREMATURE"
    assert summary["repair_ladder_update_status"] == "PASS_UPDATED"
    assert summary["epc_next_lane_status"] == "PASS_NO_RUNTIME_PACKET"
    assert summary["next_lawful_move"] == "AUTHOR_MATH_CORPUS_SOURCE_BINDING_V1"
    assert summary["blockers"] == []
    assert summary["claim_ceiling_status"] == "PRESERVED"

    assert summary["packet_path_if_any"] is None
    assert summary["packet_sha256_if_any"] is None
    assert summary["kaggle_dataset_name_if_any"] is None
    assert summary["one_cell_runbook_if_any"] is None
    assert summary["runtime_authority"] is False
    assert summary["training_authority"] is False
    assert summary["promotion_authority"] is False
    assert summary["adapter_mutation_authority"] is False


def test_hypothesis_ledger_keeps_training_plausible_but_unauthorized() -> None:
    ledger = read_json("reports/v17_7_4_math_pretraining_hypothesis_ledger.json")
    hypotheses = {row["id"]: row for row in ledger["hypotheses"]}

    assert hypotheses["H0_OFFICIAL_BASELINE"]["official_score"] == "28/100"
    assert hypotheses["H0_OFFICIAL_BASELINE"]["score_revision_authorized"] is False
    assert hypotheses["H1_PROMPT_FORMAT_SUPPRESSION"]["status"] == "UNTESTED_OR_PARTIAL"
    assert hypotheses["H2_PARSER_SCORING_RECOVERABILITY"]["status"] == "MOSTLY_BOUND_NOT_BOTTLENECK"
    assert hypotheses["H3_CORPUS_TRAINING_DATA_QUALITY"]["status"] == "UNTESTED"
    assert hypotheses["H4_TRAINING_REQUIRED"]["status"] == "PLAUSIBLE_DOWNSTREAM"
    assert hypotheses["H4_TRAINING_REQUIRED"]["training_authority"] is False

    correction = read_json("reports/v17_7_4_training_not_yet_authorized_correction_receipt.json")
    assert correction["status"] == "PASS"
    assert correction["training_plausible_downstream"] is True
    assert correction["training_authority"] is False
    assert correction["olympiad_training_authority"] is False
    assert correction["gsm8k_foundation_before_olympiad"] is True


def test_parser_plus_22_claim_is_blocked_by_official_score_surface() -> None:
    correction = read_json("reports/v17_7_4_math_parser_recoverability_correction.json")
    ceiling = read_json("reports/v17_7_4_math_parser_recoverability_ceiling.json")
    block = read_json("reports/v17_7_4_math_parser_plus_22_claim_block.json")

    assert correction["status"] == "PASS"
    assert correction["parser_format_failure_count"] == 22
    assert correction["parser_format_failure_official_correct_count"] == 22
    assert correction["parser_format_failure_official_wrong_count"] == 0
    assert correction["potential_official_score_gain_under_fixed_rule"] == 0
    assert correction["claim"] == "PARSER_NOT_BOTTLENECK"

    assert ceiling["parser_reported_plus_22_rows"] == 22
    assert ceiling["parser_plus_22_official_score_gain_authorized"] is False
    assert ceiling["maximum_bound_official_gain_from_parser_format_failures"] == 0
    assert block["status"] == "PASS_BLOCKED"
    assert block["score_replay_required_for_any_future_parser_gain_claim"] is True


def test_prompt_probe_and_corpus_audit_are_design_only() -> None:
    prompt_design = read_json("reports/v17_7_4_math_prompt_format_probe_design_only.json")
    prompt_gate = read_json("reports/v17_7_4_math_prompt_format_probe_gate.json")
    corpus_request = read_json("reports/v17_7_4_math_corpus_audit_request_index.json")
    corpus_no_training = read_json("reports/v17_7_4_math_corpus_audit_not_training_receipt.json")

    assert prompt_design["status"] == "DESIGN_ONLY"
    assert prompt_design["runtime_authority"] is False
    assert prompt_design["packet_generated"] is False
    assert prompt_design["no_adapters"] is True
    assert prompt_gate["status"] == "PASS_DESIGN_ONLY_NO_RUNTIME_AUTHORITY"
    assert prompt_gate["epc_explicit_authorization_required"] is True
    assert prompt_gate["training_allowed"] is False

    assert corpus_request["status"] == "SOURCE_NOT_BOUND"
    assert corpus_request["row_level_training_corpus_bound"] is False
    assert corpus_request["next_lane"] == "AUTHOR_MATH_CORPUS_SOURCE_BINDING_V1"
    assert corpus_no_training["status"] == "PASS_NO_TRAINING"
    assert corpus_no_training["no_new_training_data_generated"] is True
    assert corpus_no_training["training_authority"] is False


def test_training_court_and_repair_ladder_preserve_claim_ceiling() -> None:
    court = read_json("reports/v17_7_4_math_training_prerequisite_decision_court.json")
    training_false = read_json("reports/v17_7_4_math_training_authority_still_false_receipt.json")
    repair = read_json("reports/v17_7_4_math_repair_ladder_update_after_pretraining_court.json")
    epc = read_json("reports/v17_7_4_epc_decision_after_math_pretraining_hypothesis_court.json")

    assert court["status"] == "TRAINING_REQUEST_PREMATURE"
    assert court["training_request_next_draft_allowed"] is False
    assert court["training_authority"] is False
    assert training_false["status"] == "PASS"
    assert training_false["training_authority"] is False
    assert training_false["promotion_authority"] is False
    assert training_false["adapter_mutation_authority"] is False

    assert repair["status"] == "PASS_UPDATED"
    assert repair["gsm8k_foundation_before_olympiad"] is True
    assert repair["olympiad_aime_math_training_downstream_only"] is True
    assert repair["target_lobe_authority"] is False
    assert repair["training_authority"] is False

    assert epc["status"] == "PASS_DECIDED"
    assert epc["selected_next_lane"] == "AUTHOR_MATH_CORPUS_SOURCE_BINDING_V1"
    assert epc["runtime_allowed_by_this_lane"] is False
    assert epc["training_allowed_by_this_lane"] is False


def test_no_forbidden_artifacts_are_generated() -> None:
    summary = read_json("reports/v17_7_4_math_pretraining_hypothesis_court_builder_summary.json")
    generated_paths = [Path(path) for path in summary["files_changed"]]

    assert all(not path.match("packets/*") for path in generated_paths)
    assert all(not path.match("datasets/*") for path in generated_paths)
    assert all(path.suffix != ".safetensors" for path in generated_paths)
    assert all("hf_upload" not in path.as_posix().lower() for path in generated_paths)
    assert summary["runtime_packet_generated"] is False
    assert summary["training_packet_generated"] is False
    assert summary["dataset_packet_generated"] is False
    assert summary["safetensors_generated"] is False
    assert summary["hf_upload_authorized"] is False
