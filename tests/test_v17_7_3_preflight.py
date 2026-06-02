from tests.v17_7_3_utils import assert_no_authority, read_json


def test_v17_7_3_preflight_binds_current_repo_and_packet() -> None:
    receipt = read_json("reports/v17_7_3_preflight_repo_truth_receipt.json")
    assert receipt["status"] == "PASS"
    assert receipt["current_head"]
    assert receipt["current_branch"]
    assert receipt["packet_sha256"] == "c593b7eca57da9b6087146b6c8a592515228eb37bd6ecc89fff64848ee34e47c"
    assert receipt["prompt_sha256"] == "219774b9a8595492e19080c3169a709afb8e2c842e8e9fa741c9dbb6950e8a15"
    assert_no_authority(receipt)
