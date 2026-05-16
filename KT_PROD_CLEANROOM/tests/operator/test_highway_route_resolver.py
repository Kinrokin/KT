from __future__ import annotations

from tools.operator import highway_common as highway


def test_route_resolver_emits_one_primary_lane_with_secondary_advisory(tmp_path):
    receipt = highway.write_route_receipt(
        {
            "work_order_id": "TEST_ROUTE",
            "operator_intent": "prep FP0 commercial claim scanner",
            "touches_fp0": True,
            "touches_commercial_surface": True,
        },
        tmp_path,
    )
    assert receipt["selected_superlane"] == "COMMERCIAL_DELIVERY"
    assert "LAB_AND_ADAPTIVE_RATIFICATION" in receipt["secondary_superlanes"]
    assert receipt["canonical_effect"] == "NONE"
