from tools.operator import cohort0_b04_r6_canary_evidence_review_packet_validation as scaffold


def test_validation_scaffold_is_prep_only() -> None:
    receipt = scaffold.scaffold_receipt()
    assert receipt["authority"] == "PREP_ONLY"
    assert receipt["validation_ready"] is True
    assert receipt["canonical_validation_not_executed_by_scaffold"] is True
    assert receipt["cannot_authorize_runtime_cutover"] is True
    assert receipt["cannot_open_r6"] is True
    assert receipt["cannot_authorize_package_promotion"] is True
