from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_v1774_claim_ceiling_preserved_and_authorities_false() -> None:
    paths = [
        ROOT / "reports" / "v17_7_4_claim_ceiling_receipt.json",
        ROOT / "reports" / "v17_7_4_next_move_decision_receipt.json",
        ROOT / "reports" / "v17_7_4_truegen_execfix_builder_summary.json",
    ]
    for path in paths:
        data = json.loads(path.read_text())
        assert data["claim_ceiling_preserved"] is True
        assert data["adapter_training_authorized"] is False
        assert data["router_training_authorized"] is False
        assert data["promotion_authority"] is False
        assert data["runtime_authority"] is False
        assert data["v18_runtime_authority"] is False
