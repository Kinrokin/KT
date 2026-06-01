from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_v17_5_claim_ceiling_and_v18_hold_are_preserved():
    summary = json.loads((ROOT / "reports/v17_5_builder_summary.json").read_text(encoding="utf-8"))
    hold = json.loads((ROOT / "reports/v17_5_v18_hold_receipt.json").read_text(encoding="utf-8"))
    no_promo = json.loads((ROOT / "reports/v17_5_no_route_promotion_receipt.json").read_text(encoding="utf-8"))
    assert summary["claim_ceiling_status"] == "UNCHANGED"
    assert summary["runtime_authority"] is False
    assert summary["promotion_authority"] is False
    assert summary["adapter_training_authorized"] is False
    assert summary["learned_router_superiority_claim"] is False
    assert hold["v18_runtime_authority"] is False
    assert no_promo["route_promotion_authorized"] is False
    assert no_promo["adapter_promotion_authorized"] is False
