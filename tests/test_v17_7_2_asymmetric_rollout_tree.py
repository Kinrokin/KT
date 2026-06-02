from tests.v17_7_2_utils import assert_no_authority, read_json


def test_v17_7_2_asymmetric_rollout_samples_high_risk_before_pruning() -> None:
    receipt = read_json("reports/v17_7_2_asymmetric_rollout_tree.json")
    high_risk = [row for row in receipt["branches"] if row["risk"] >= 0.70]
    assert high_risk
    assert all(row["samples"] >= 80 and row["pruned"] is False for row in high_risk)
    assert receipt["status"] == "PASS"
    assert_no_authority(receipt)
