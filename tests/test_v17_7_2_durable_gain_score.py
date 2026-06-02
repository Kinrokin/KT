from tests.v17_7_2_utils import assert_no_authority, read_json


def test_v17_7_2_durable_gain_score_is_negative_for_current_candidate() -> None:
    receipt = read_json("reports/v17_7_2_durable_gain_scorecard.json")
    assert receipt["DGS"] < 0
    assert receipt["P_fail"] >= 0.70
    assert receipt["ope_corrected_gain"] <= 0
    assert receipt["pass_for_replay_ready"] is False
    assert receipt["status"] == "FAIL_DIAGNOSTIC_ONLY"
    assert_no_authority(receipt)
