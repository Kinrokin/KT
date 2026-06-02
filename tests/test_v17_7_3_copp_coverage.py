from tests.v17_7_3_authority_utils import authority_report


def test_copp_has_full_arm_coverage_but_no_fresh_authority() -> None:
    receipt = authority_report("v17_7_3_copp_coverage_certificate.json")
    assert receipt["status"] == "PASS"
    assert receipt["coverage_ratio"] == 1.0
    assert receipt["every_row_has_all_arms"] is True
    assert receipt["replay_authority_gate_pass"] is False
