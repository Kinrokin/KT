from tests.v17_7_2_utils import assert_no_authority, read_json


def test_v17_7_2_row_recomputation_supremacy_matches_known_scores() -> None:
    receipt = read_json("reports/v17_7_2_row_recomputation_supremacy_receipt.json")
    assert receipt["row_count"] == 260
    assert receipt["recomputed_baseline_score"] == 161
    assert receipt["recomputed_candidate_score"] == 162
    assert receipt["row_level_truth_over_summary"] is True
    assert receipt["status"] == "PASS"
    assert_no_authority(receipt)
