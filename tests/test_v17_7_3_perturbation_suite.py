from tests.v17_7_3_utils import assert_no_authority, read_json


def test_v17_7_3_perturbation_suite_has_required_families() -> None:
    manifest = read_json("reports/v17_7_3_perturbation_suite_manifest.json")
    assert len(manifest["perturbation_families"]) == 7
    assert "semantic_preserving_paraphrase" in manifest["perturbation_families"]
    assert "route_target_change" in manifest["invalid_perturbations_blocked"]
    assert_no_authority(manifest)
