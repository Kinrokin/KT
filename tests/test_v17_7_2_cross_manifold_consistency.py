from tests.v17_7_2_utils import assert_no_authority, read_json


def test_v17_7_2_cross_manifold_consistency_records_disagreement() -> None:
    receipt = read_json("reports/v17_7_2_cross_manifold_consistency.json")
    assert receipt["disagreement_entropy"] > 0.5
    assert receipt["manifold_votes"]["DGS"] == "FAIL"
    assert receipt["manifold_votes"]["VoI"] == "DATA_VALUE_POSITIVE"
    assert receipt["status"] == "DIAGNOSTIC_ONLY"
    assert_no_authority(receipt)
