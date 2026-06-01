from __future__ import annotations

from pathlib import Path

from scripts.v17_7_oats_sddr_common import read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_claim_ceiling_and_no_promotion_are_preserved() -> None:
    claim = read_json(ROOT / "reports" / "v17_7_claim_admissibility_casefile.json")
    no_promote = read_json(ROOT / "reports" / "v17_7_do_not_promote_receipt.json")
    registry_delta = read_json(ROOT / "registry" / "artifact_authority_registry_v17_7_delta_receipt.json")
    assert claim["claim_ceiling_preserved"] is True
    assert "learned-router superiority" in claim["blocked_claims"]
    assert no_promote["route_promotion_authorized"] is False
    assert no_promote["adapter_promotion_authorized"] is False
    assert registry_delta["claim_ceiling_preserved"] is True
    assert registry_delta["commercial_claim_added"] is False
    assert registry_delta["learned_router_superiority_claim_added"] is False
