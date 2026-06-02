from tests.v17_7_2_utils import assert_no_authority, read_json


def test_v17_7_2_pre_registration_blocks_post_hoc_hypotheses() -> None:
    receipt = read_json("admission/v17_7_2_pre_registered_hypotheses.json")
    assert receipt["lock_status"] == "PASS"
    assert receipt["post_hoc_hypotheses_allowed"] is False
    assert all(row["pre_registered"] and not row["post_hoc"] for row in receipt["hypotheses"])
    assert_no_authority(receipt)
