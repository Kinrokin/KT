from tests.v17_7_3_utils import assert_no_authority, read_json


def test_v17_7_3_active_learning_loop_is_evidence_only() -> None:
    receipt = read_json("reports/v17_7_3_active_learning_loop_receipt.json")
    assert receipt["status"] == "PASS"
    assert receipt["policy_optimization_authorized"] is False
    assert receipt["active_learning_loop"][0] == "select_by_EIG"
    assert_no_authority(receipt)
