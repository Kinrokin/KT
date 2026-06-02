from tests.v17_7_2_utils import assert_no_authority, read_json


def test_v17_7_2_ope_baseline_is_executed_and_fail_closed() -> None:
    receipt = read_json("reports/v17_7_2_ope_baseline.json")
    assert receipt["row_count"] == 260
    assert receipt["formula_ips"].startswith("V_hat =")
    assert receipt["formula_dr"].startswith("V_hat =")
    assert receipt["effective_sample_size"] > 0
    assert receipt["ope_corrected_gain"] <= receipt["raw_replay_gain"]
    assert receipt["status"] == "FAIL_DIAGNOSTIC_ONLY"
    assert_no_authority(receipt)
