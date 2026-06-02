from tests.v17_7_3_utils import assert_no_authority, read_json


def test_v17_7_3_preflight_binds_current_repo_and_packet() -> None:
    receipt = read_json("reports/v17_7_3_preflight_repo_truth_receipt.json")
    assert receipt["status"] == "PASS"
    assert receipt["current_head"]
    assert receipt["current_branch"]
    assert receipt["program_id"] == "KT_V17_7_3_MEASUREMENT_AUTHORITY_ADJUDICATION_AND_NEXT_EVIDENCE_MOVE_V1_1"
    assert receipt["packet_sha256"] == "a213b692753edd74d2e4479d7918ac0cb9491d6587b365d7d353fd34fe3ea88d"
    assert receipt["prompt_sha256"] == "bbd15571a970aaa5948adce62e587be7d6f94fc5645b224f9ae83430ce64d4fe"
    assert_no_authority(receipt)
