from tests.v17_7_3_utils import assert_no_authority, read_json


def test_v17_7_3_conformal_calibration_inherits_wide_set() -> None:
    receipt = read_json("reports/v17_7_3_conformal_calibration_receipt.json")
    assert receipt["target_coverage"] == 0.9
    assert receipt["current_route_set_width"] >= 3
    assert receipt["calibration_rows"] == 80
    assert_no_authority(receipt)
