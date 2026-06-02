from tests.v17_7_2_utils import assert_no_authority, read_json


def test_v17_7_2_metacognition_overfit_scan_blocks_authority() -> None:
    receipt = read_json("reports/v17_7_2_metacognition_overfit_scan.json")
    assert receipt["metacognition_grants_authority"] is False
    assert receipt["dgs_gameable"] is True
    assert receipt["status"] == "FAIL_DIAGNOSTIC_ONLY"
    assert_no_authority(receipt)
