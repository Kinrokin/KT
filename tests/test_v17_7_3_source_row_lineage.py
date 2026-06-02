from tests.v17_7_3_authority_utils import authority_report


def test_source_row_lineage_covers_400_predictions_and_2000_arm_rows() -> None:
    receipt = authority_report("v17_7_3_source_row_lineage_receipt.json")
    counts = set(receipt["arm_rows_per_sample"])
    assert receipt["status"] == "PASS"
    assert receipt["unique_prediction_sample_ids"] == 400
    assert receipt["unique_arm_sample_ids"] == 400
    assert counts == {5}
    assert receipt["missing_arm_samples"] == []
