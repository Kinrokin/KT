from tests.v17_7_2_utils import assert_no_authority, read_json


def test_v17_7_2_predictive_failure_probability_blocks_ready_status() -> None:
    receipt = read_json("reports/v17_7_2_predictive_failure_probability.json")
    assert receipt["P_fail"] >= 0.70
    assert receipt["decision"] == "DIAGNOSTIC_ONLY"
    assert receipt["status"] == "FAIL_RISK_HIGH"
    assert receipt["formula"].startswith("sigmoid(w1*cv_generalization_delta")
    assert_no_authority(receipt)
