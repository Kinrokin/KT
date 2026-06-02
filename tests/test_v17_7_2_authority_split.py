from tests.v17_7_2_utils import assert_no_authority, read_json


def test_v17_7_2_authority_split_allows_active_learning_only() -> None:
    receipt = read_json("reports/v17_7_2_authority_split_receipt.json")
    assert receipt["authority_tier"] == "ACTIVE_LEARNING_TRIGGERED"
    assert receipt["replay_ready"] is False
    assert "V18_READY" in receipt["forbidden_authority_tiers"]
    assert_no_authority(receipt)
