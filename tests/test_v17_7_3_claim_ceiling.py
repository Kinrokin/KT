from tests.v17_7_3_utils import assert_no_authority, read_json


def test_v17_7_3_final_decision_preserves_claim_ceiling() -> None:
    final = read_json("reports/v17_7_3_final_decision_receipt.json")
    summary = read_json("reports/v17_7_3_builder_summary.json")
    assert final["outcome"] == "KTG3FULL_V17_7_3_EVIDENCE_ACQUISITION_READY__RUN_TARGETED_BOUNDARY_ROW_FURNACE_NEXT__CLAIM_CEILING_PRESERVED"
    assert final["next_lawful_move"] == "RUN_TARGETED_BOUNDARY_ROW_FURNACE_NEXT"
    assert summary["kaggle_dataset_name"] == "ktv1773-evidence-v1"
    assert_no_authority(final)
    assert_no_authority(summary)
