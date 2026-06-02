from tests.v17_7_3_authority_utils import authority_report


def test_scorer_determinism_recomputes_oracle_rows_without_mismatch() -> None:
    receipt = authority_report("v17_7_3_scorer_determinism_receipt.json")
    scorecard = authority_report("v17_7_3_scorecard_recomputation_receipt.json")
    assert receipt["status"] == "PASS"
    assert receipt["score_consistency_pass"] is True
    assert receipt["recomputation_mismatches"] == []
    assert scorecard["recomputed"]["correct_counts"]["formal_math_repair_adapter_global"] == 274
    assert scorecard["recomputed"]["oracle_correct_count"] == 345
