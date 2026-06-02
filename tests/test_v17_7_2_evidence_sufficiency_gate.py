from tests.v17_7_2_utils import assert_no_authority, read_json


def test_v17_7_2_evidence_sufficiency_triggers_active_learning() -> None:
    receipt = read_json("reports/v17_7_2_evidence_sufficiency_gate.json")
    assert receipt["enough_for_replay_ready"] is False
    assert receipt["enough_for_active_learning"] is True
    assert "NESTED_CV_FAILED" in receipt["blockers"]
    assert receipt["status"] == "ACTIVE_LEARNING_TRIGGERED"
    assert_no_authority(receipt)
