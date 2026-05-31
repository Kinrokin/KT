from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_route_rescuer_court_requires_fresh_evidence_before_admission():
    court = json.loads((ROOT / "admission/route_rescuer_court.json").read_text(encoding="utf-8"))
    required = set(court["required_evidence"])
    assert "v17_oracle_conversion_scorecard.json" in required
    assert "v17_base_preservation_receipt.json" in required
    assert "v17_harmful_activation_receipt.json" in required
    assert "v17_oracle_leakage_scan.json" in required
    assert court["runtime_authority"] is False
    assert court["promotion_authority"] is False
    assert court["claim_ceiling_preserved"] is True
