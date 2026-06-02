from tests.v17_7_3_utils import assert_no_authority, read_json


def test_v17_7_3_boundary_coverage_meets_minimums() -> None:
    scorecard = read_json("reports/v17_7_3_boundary_coverage_scorecard.json")
    assert scorecard["boundary_coverage_pass"] is True
    for key, target in scorecard["boundary_targets"].items():
        assert scorecard["boundary_counts"][key] >= target
    assert_no_authority(scorecard)
