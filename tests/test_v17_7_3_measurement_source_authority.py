from tests.v17_7_3_authority_utils import assert_no_authority, authority_report


def test_source_route_outcome_replay_is_tier_limited() -> None:
    review = authority_report("v17_7_3_measurement_source_authority_review.json")
    tier = authority_report("v17_7_3_measurement_provenance_tier_receipt.json")
    assert review["measurement_sources"] == ["SOURCE_ROUTE_OUTCOME_REPLAY"]
    assert review["model_scored_rows"] is True
    assert review["fresh_generation_authority"] is False
    assert tier["evidence_tier"] == "TIER_2_SOURCE_ROUTE_OUTCOME_REPLAY"
    assert "fresh benchmark authority" in tier["denied_authority"]
    assert_no_authority(review)
    assert_no_authority(tier)
