from tests.v17_7_2_utils import assert_no_authority, read_json


def test_v17_7_2_temporal_drift_alarm_is_emitted() -> None:
    trace = read_json("reports/v17_7_2_temporal_drift_trace.json")
    alarm = read_json("reports/v17_7_2_temporal_drift_alarm_receipt.json")
    assert len(trace["trace"]) >= 3
    assert alarm["alarm_triggered"] is True
    assert "route_distribution_kl" in alarm["alarm_reason"]
    assert_no_authority(alarm)
