from tests.v17_7_3_authority_utils import authority_report


def test_covariate_shift_gate_remains_unresolved_for_source_replay() -> None:
    profile = authority_report("v17_7_3_covariate_shift_profile.json")
    assert profile["status"] == "PASS"
    assert profile["band_counts"]
    assert profile["shift_status"] == "UNRESOLVED_SOURCE_REPLAY_LIMITED"
    assert profile["replay_authority_gate_pass"] is False
