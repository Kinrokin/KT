from tests.v17_7_3_authority_utils import authority_report


def test_arm_efficiency_and_token_cost_matrix_is_row_derived() -> None:
    matrix = authority_report("v17_7_3_arm_efficiency_and_token_cost_matrix.json")
    assert matrix["status"] == "PASS"
    for arm, row in matrix["matrix"].items():
        assert row["total_tokens"] > 0
        assert row["tokens_per_correct"] > 0
        assert 0 <= row["accuracy"] <= 1
