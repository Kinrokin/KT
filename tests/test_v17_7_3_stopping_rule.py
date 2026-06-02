from tests.v17_7_3_utils import assert_no_authority, read_json


def test_v17_7_3_stopping_rule_does_not_stop_current_bad_state() -> None:
    receipt = read_json("reports/v17_7_3_stopping_rule_receipt.json")
    contract = read_json("admission/v17_7_3_stopping_rule_contract.json")
    assert receipt["current_pfail_forces_continue"] is True
    assert receipt["current_dgs_forces_continue"] is True
    assert any("P_fail > 0.70" in rule for rule in contract["do_not_stop_if"])
    assert_no_authority(receipt)
    assert_no_authority(contract)
