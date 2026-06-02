from tests.v17_7_2_utils import assert_no_authority, read_json


def test_v17_7_2_counterfactual_replay_executes_row_and_cluster_flips() -> None:
    matrix = read_json("reports/v17_7_2_counterfactual_replay_matrix.json")
    cluster = read_json("reports/v17_7_2_counterfactual_cluster_replay.json")
    dependency = read_json("reports/v17_7_2_counterfactual_dependency_scorecard.json")
    assert matrix["row_count"] == len(matrix["individual_flips"])
    assert matrix["row_count"] >= 20
    assert cluster["clusters"]
    assert dependency["fatal_dependency_detected"] is True
    assert_no_authority(matrix)
