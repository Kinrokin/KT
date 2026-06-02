from tests.v17_7_3_authority_utils import authority_report


def test_negative_transfer_is_recorded_for_each_arm() -> None:
    receipt = authority_report("v17_7_3_negative_transfer_by_arm_receipt.json")
    atlas = authority_report("v17_7_3_arm_niche_atlas.json")
    assert receipt["status"] == "PASS"
    assert set(receipt["negative_transfer"]) == set(atlas["arms"])
    assert atlas["arms"]["formal_math_repair_adapter_global"]["global_promotion_authorized"] is False
    assert atlas["arms"]["base_kt_hat_compact"]["negative_transfer_vs_base_raw"] > 0
