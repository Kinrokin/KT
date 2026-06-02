from tests.v17_7_3_utils import assert_no_authority, read_json


def test_v17_7_3_adversarial_boundary_probing_required() -> None:
    receipt = read_json("reports/v17_7_3_adversarial_probing_receipt.json")
    assert receipt["adversarial_boundary_probing_required"] is True
    assert "base_raw__route_regret" in receipt["boundary_targets"]
    assert_no_authority(receipt)
