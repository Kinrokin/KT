from __future__ import annotations

from pathlib import Path

from scripts.v17_7_oats_sddr_common import STATIC_ROUTES, read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_oats_centroid_shift_is_computed_from_rows() -> None:
    receipt = read_json(ROOT / "reports" / "oats_centroid_shift_receipt.json")
    assert receipt["schema_id"] == "kt.v17_7.oats_centroid_shift_receipt.v1"
    assert receipt["claim_ceiling_preserved"] is True
    assert receipt["oracle_correctness_used_as_input_feature"] is False
    assert set(receipt["routes"]) == set(STATIC_ROUTES)
    assert receipt["feature_names"]
    for route in STATIC_ROUTES:
        route_receipt = receipt["routes"][route]
        assert route_receipt["success_rows"] > 0
        assert route_receipt["shifted_centroid"]
