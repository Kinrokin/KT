from tests.v17_7_2_utils import read_json, read_jsonl


def test_v17_7_2_golden_fixture_matches_summary() -> None:
    fixture = read_json("fixtures/v17_7_2_expected_outputs.json")
    summary = read_json("reports/v17_7_2_builder_summary.json")
    rows = read_jsonl("fixtures/v17_7_2_mini_policy_rows.jsonl")
    assert fixture["expected_outcome"] == summary["outcome"]
    assert fixture["expected_authority_tier"] == summary["authority_tier"]
    assert fixture["expected_replay_ready"] == summary["replay_ready"]
    assert len(rows) == 5
