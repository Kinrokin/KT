from tests.v17_7_2_utils import assert_no_authority, read_json


def test_v17_7_2_do_nothing_counterfactual_is_competitive() -> None:
    receipt = read_json("admission/v17_7_2_do_nothing_counterfactual.json")
    assert receipt["observed_gain"] == 1
    assert receipt["minimum_detectable_effect_rows"] > receipt["observed_gain"]
    assert receipt["do_nothing_advantage"] > 0
    assert receipt["status"] == "PASS_EXECUTED"
    assert_no_authority(receipt)
