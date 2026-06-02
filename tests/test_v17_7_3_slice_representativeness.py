from tests.v17_7_3_authority_utils import authority_report


def test_slice_representativeness_blocks_generalization_claims() -> None:
    score = authority_report("v17_7_3_slice_representativeness_score.json")
    consistency = authority_report("v17_7_3_cross_run_consistency_matrix.json")
    assert score["status"] == "PASS"
    assert score["row_count"] == 400
    assert score["generalization_authority"] is False
    assert consistency["comparable"] is False
