from tests.v17_7_3_utils import assert_no_authority, read_json, read_jsonl


def test_v17_7_3_golden_fixture_has_required_cases() -> None:
    rows = read_jsonl("fixtures/v17_7_3_mini_acquisition_rows.jsonl")
    expected = read_json("fixtures/v17_7_3_expected_outputs.json")
    cases = {row["fixture_case"] for row in rows}
    assert len(rows) == expected["fixture_case_count"]
    assert {"label_contamination", "holdout_violation", "state_diff", "math_act"} <= cases
    assert_no_authority(expected)
