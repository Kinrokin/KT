from tests.v17_7_3_utils import assert_no_authority, read_json


def test_v17_7_3_ope_baseline_requires_new_rows() -> None:
    baseline = read_json("reports/v17_7_3_ope_baseline.json")
    assert baseline["status"] == "PASS"
    assert baseline["inherited_ope_corrected_gain"] < 0
    assert baseline["new_rows_required_for_update"] is True
    assert_no_authority(baseline)
