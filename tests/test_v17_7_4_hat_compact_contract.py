from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_hat_compact_contract_blocks_governance_bloat_in_scored_output() -> None:
    receipt = json.loads((ROOT / "reports" / "kt_hat_compact_contract_receipt.json").read_text(encoding="utf-8"))
    joined = " ".join(receipt["contract"]).lower()
    assert "no decorative governance language" in joined
    assert "parser-friendly" in joined
    assert receipt["claim_ceiling_preserved"] is True
    assert receipt["promotion_authority"] is False
