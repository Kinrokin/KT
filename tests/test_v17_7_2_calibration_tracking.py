from tests.v17_7_2_utils import assert_no_authority, read_json


def test_v17_7_2_calibration_tracking_is_baselined() -> None:
    receipt = read_json("reports/v17_7_2_predictive_calibration_receipt.json")
    assert receipt["calibration_status"] == "BASELINED_DIAGNOSTIC_ONLY"
    assert receipt["observed_v1771_failures_bound"] is True
    assert_no_authority(receipt)
