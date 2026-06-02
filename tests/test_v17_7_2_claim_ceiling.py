from tests.v17_7_2_utils import assert_no_authority, read_json


def test_v17_7_2_claim_ceiling_preserved_in_final_decision() -> None:
    receipt = read_json("reports/v17_7_2_final_decision_receipt.json")
    assert receipt["outcome"] == "KTG3FULL_V17_7_2_ACTIVE_LEARNING_TRIGGERED__EVIDENCE_ACQUISITION_NEXT__CLAIM_CEILING_PRESERVED"
    assert receipt["replay_ready"] is False
    assert receipt["next_lawful_move"] == "EVIDENCE_ACQUISITION_NEXT"
    assert_no_authority(receipt)
