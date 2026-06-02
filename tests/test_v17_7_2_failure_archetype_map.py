from tests.v17_7_2_utils import assert_no_authority, read_json


def test_v17_7_2_failure_archetype_map_has_required_classes() -> None:
    receipt = read_json("reports/v17_7_2_failure_archetype_map.json")
    archetypes = {row["archetype"] for row in receipt["archetypes"]}
    for expected in {"structural", "semantic", "perturbation", "distributional", "OPE", "conformal_uncertainty", "VoI_insufficiency"}:
        assert expected in archetypes
    assert_no_authority(receipt)
