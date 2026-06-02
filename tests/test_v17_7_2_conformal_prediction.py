from tests.v17_7_2_utils import assert_no_authority, read_json


def test_v17_7_2_conformal_prediction_fails_wide_sets_closed() -> None:
    receipt = read_json("reports/v17_7_2_conformal_prediction_sets.json")
    assert receipt["target_coverage"] >= 0.90
    assert receipt["empirical_coverage"] >= 0.90
    assert receipt["route_set_width"] >= 3
    assert receipt["wide_route_set_forces_base_raw_or_diagnostic"] is True
    assert_no_authority(receipt)
