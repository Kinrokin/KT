from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_adapter_load_contract_blocks_base_fallback_as_adapter_evidence() -> None:
    schema = json.loads((ROOT / "schemas" / "kt.v17_7_4.adapter_loader_receipt.schema.json").read_text(encoding="utf-8"))
    receipt = json.loads((ROOT / "reports" / "v17_7_4_adapter_load_contract_receipt.json").read_text(encoding="utf-8"))
    assert schema["properties"]["base_fallback_as_adapter_evidence_allowed"]["const"] is False
    assert receipt["base_fallback_as_adapter_evidence_allowed"] is False
    assert receipt["adapter_arms_require_peft_loader"] is True
    assert receipt["real_arm_adapter_sources_required"] is True
    assert receipt["claim_ceiling_preserved"] is True
