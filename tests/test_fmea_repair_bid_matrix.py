from __future__ import annotations

from g32_test_utils import load_json


def test_fmea_repair_bid_matrix_prioritizes_without_training_authority() -> None:
    matrix = load_json("reports/kt_fmea_repair_bid_matrix.json")

    assert matrix["schema_id"] == "kt.fmea_repair_bid_matrix.v1"
    assert matrix["training_authorized"] is False
    assert matrix["claim_ceiling_preserved"] is True
    for row in matrix["rows"]:
        expected = (
            row["severity"]
            * row["recurrence"]
            * row["importance"]
            * row["regret_potential"]
            * row["scar_clarity"]
            * row["regression_safety"]
        ) / row["repair_cost"]
        assert row["failure_repair_value"] == expected
