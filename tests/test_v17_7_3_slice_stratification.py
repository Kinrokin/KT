from tests.v17_7_3_utils import assert_no_authority, read_json


def test_v17_7_3_slice_stratification_meets_targets_by_design() -> None:
    manifest = read_json("reports/v17_7_3_slice_stratification_manifest.json")
    targets = manifest["slice_targets"]
    counts = manifest["slice_counts"]
    assert manifest["status"] == "PASS"
    for key, target in targets.items():
        assert counts[key] >= target
    assert_no_authority(manifest)
