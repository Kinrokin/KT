import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str):
    return json.loads((ROOT / path).read_text(encoding="utf-8-sig"))


def read_jsonl(path: str):
    return [json.loads(line) for line in (ROOT / path).read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def test_scratchpad_failure_review_binds_measured_negative_result():
    summary = read_json("reports/v17_7_4_math_scratchpad_failure_review_builder_summary.json")
    scorecard = read_json("reports/v17_7_4_math_scratchpad_scorecard_binding.json")
    failure = read_json("reports/v17_7_4_math_scratchpad_failure_summary.json")

    assert summary["status"] == "PASS"
    assert summary["outcome"] == (
        "KT_MATH_SCRATCHPAD_MICROFURNACE_REVIEWED__FAILED_CANDIDATES_QUARANTINED__"
        "NEXT_HYPOTHESIS_SELECTED__CLAIM_CEILING_PRESERVED"
    )
    assert scorecard["source_matches_recomputed"] is True
    assert scorecard["control_remains_best"] is True
    assert scorecard["recomputed_correct_counts"] == {
        "A2_math_act_full_reasoning": 3,
        "A3_math_act_reasoning_preserving_compact": 2,
        "A4_formal_math_reasoning_preserving_compact": 5,
        "A_true_known_good_math_act_byte_repro": 13,
    }
    assert failure["status"] == "NEGATIVE_RESULT_CONFIRMED"
    assert failure["final_summary_conflict_resolution"] == "DO_NOT_RERUN_UNCHANGED"


def test_scratchpad_candidates_are_quarantined_with_damage_rescue_counts():
    quarantine = read_json("reports/v17_7_4_math_scratchpad_candidate_quarantine_receipt.json")
    damage = read_json("reports/v17_7_4_math_scratchpad_damage_rescue_matrix.json")

    assert quarantine["control_status"] == "CONTROL_REMAINS_BEST"
    assert quarantine["all_candidates_worse_than_control"] is True
    assert all(status == "QUARANTINE_FAILED_CORRECTNESS_AND_COST" for status in quarantine["candidate_statuses"].values())
    assert damage["matrix"]["A2_math_act_full_reasoning"]["control_damaged_rows"] == 11
    assert damage["matrix"]["A2_math_act_full_reasoning"]["candidate_rescued_rows"] == 1
    assert damage["matrix"]["A3_math_act_reasoning_preserving_compact"]["control_damaged_rows"] == 11
    assert damage["matrix"]["A3_math_act_reasoning_preserving_compact"]["candidate_rescued_rows"] == 0
    assert damage["matrix"]["A4_formal_math_reasoning_preserving_compact"]["control_damaged_rows"] == 9
    assert damage["matrix"]["A4_formal_math_reasoning_preserving_compact"]["candidate_rescued_rows"] == 1


def test_scratchpad_review_blocks_runtime_and_selects_control_preserving_hypothesis():
    no_runtime = read_json("reports/v17_7_4_math_scratchpad_no_runtime_authority_receipt.json")
    epc = read_json("reports/v17_7_4_math_scratchpad_epc_decision_after_failure.json")
    claim = read_json("reports/v17_7_4_math_scratchpad_claim_boundary_receipt.json")
    rows = read_jsonl("reports/v17_7_4_math_scratchpad_row_level_autopsy.jsonl")

    assert no_runtime["scratchpad_global_runtime_authority"] is False
    assert no_runtime["scratchpad_microfurnace_repeat_authority"] is False
    assert no_runtime["next_runtime_packet_generated"] is False
    assert epc["selected_next_lane"] == "DESIGN_CONTROL_PRESERVING_MATH_VERIFIER_RESCUE_OFFLINE_SIMULATION"
    assert epc["no_kaggle_runtime_packet"] is True
    assert "RERUN_MATH_SCRATCHPAD_MICROFURNACE_UNCHANGED" in epc["rejected_next_lanes"]
    assert claim["generic_final_summary_overridden"] is True
    assert len(rows) == 25
    assert all(row["training_authorized"] is False for row in rows)


def test_scratchpad_review_records_parser_and_wrapper_hygiene_limits():
    parser = read_json("reports/v17_7_4_math_scratchpad_parser_scorer_vs_reasoning_court.json")
    wrapper = read_json("reports/v17_7_4_math_scratchpad_wrapper_hygiene_receipt.json")
    token = read_json("reports/v17_7_4_math_scratchpad_token_economics_court.json")

    assert parser["status"] == "PASS_PARSER_ONLY_EXPLANATION_REJECTED"
    assert parser["control_parser_failure_rate"] == 0.52
    assert wrapper["status"] == "WRAPPER_PATH_MISMATCH_RECORDED"
    assert wrapper["path_mismatch_detected"] is True
    assert token["status"] == "PASS_NEGATIVE_TOKEN_ECONOMICS"
    assert token["scratchpad_tokens_count_in_full_tpc"] is True
