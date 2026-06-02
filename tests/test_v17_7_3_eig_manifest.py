from tests.v17_7_3_utils import assert_no_authority, read_json


def test_v17_7_3_eig_manifest_is_nonrandom_and_budgeted() -> None:
    manifest = read_json("admission/v17_7_3_targeted_boundary_row_manifest.json")
    scorecard = read_json("reports/v17_7_3_eig_scorecard.json")
    assert manifest["row_count"] == 400
    assert manifest["selection_method"] == "EIG"
    assert scorecard["selection_method"] == "EIG_NOT_RANDOM"
    assert scorecard["eig_summary"]["max"] >= scorecard["eig_summary"]["min"]
    assert_no_authority(manifest)
    assert_no_authority(scorecard)
