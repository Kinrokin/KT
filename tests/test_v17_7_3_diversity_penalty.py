from tests.v17_7_3_utils import assert_no_authority, read_json


def test_v17_7_3_diversity_penalty_is_applied() -> None:
    receipt = read_json("reports/v17_7_3_diversity_penalty_receipt.json")
    assert receipt["status"] == "PASS"
    assert receipt["redundancy_penalty_applied"] is True
    assert len(receipt["dataset_counts"]) >= 3
    assert_no_authority(receipt)
