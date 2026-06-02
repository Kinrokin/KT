from tests.v17_7_3_authority_utils import authority_report


def test_ground_truth_and_schema_drift_are_not_silently_upgraded() -> None:
    drift = authority_report("v17_7_3_ground_truth_drift_detector.json")
    temporal = authority_report("v17_7_3_temporal_drift_and_schema_receipt.json")
    assert drift["status"] == "PASS"
    assert drift["ground_truth_drift_detected"] is False
    assert "tier-limited" in drift["limitation"]
    assert temporal["temporal_drift_detected"] is False
