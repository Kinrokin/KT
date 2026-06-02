from tests.v17_7_3_authority_utils import authority_report


def test_mr_variance_records_margin_without_granting_replay_authority() -> None:
    receipt = authority_report("v17_7_3_mr_variance_confidence_bound.json")
    bound = receipt["confidence_bound"]
    assert receipt["status"] == "PASS"
    assert bound["margin"] > 0
    assert bound["ci95_low"] < bound["ci95_high"]
    assert receipt["replay_authority_gate_pass"] is False
