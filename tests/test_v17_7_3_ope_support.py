from tests.v17_7_3_utils import assert_no_authority, read_json


def test_v17_7_3_ope_support_gap_forces_acquisition() -> None:
    matrix = read_json("reports/v17_7_3_ope_support_gap_matrix.json")
    assert matrix["status"] == "PASS"
    assert matrix["support_gap_status"] == "ACQUISITION_REQUIRED"
    assert matrix["importance_weight_variance"] > 0
    assert_no_authority(matrix)
