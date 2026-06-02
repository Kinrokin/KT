from tests.v17_7_2_utils import assert_no_authority, read_json


def test_v17_7_2_synthetic_boundaries_are_negative_control_only() -> None:
    receipt = read_json("reports/v17_7_2_synthetic_manifold_boundaries.json")
    assert len(receipt["boundaries"]) >= 12
    assert receipt["synthetic_success_zones_allowed"] is False
    assert all(row["authority"] == "NEGATIVE_CONTROL_ONLY" for row in receipt["boundaries"])
    assert_no_authority(receipt)
