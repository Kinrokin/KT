from tests.v17_7_3_utils import assert_no_authority, read_json


def test_v17_7_3_holdout_is_quarantined() -> None:
    manifest = read_json("admission/v17_7_3_holdout_quarantine_manifest.json")
    receipt = read_json("reports/v17_7_3_holdout_integrity_receipt.json")
    assert manifest["split"]["final_holdout"] >= manifest["final_holdout_minimum_rows"]
    assert manifest["final_holdout_touched_before_promotion_gate"] is False
    assert receipt["holdout_violation"] is False
    assert_no_authority(manifest)
    assert_no_authority(receipt)
