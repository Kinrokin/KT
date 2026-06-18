from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_stop50_claim_ceiling_and_forbidden_authorities_preserved() -> None:
    receipt = json.loads((ROOT / "reports/ktstop50_claim_boundary_receipt.json").read_text(encoding="utf-8-sig"))
    assert receipt["status"] == "PASS_CLAIM_CEILING_PRESERVED"
    assert receipt["claim_ceiling_status"] == "PRESERVED"
    for key in [
        "runtime_authority",
        "training_authority",
        "promotion_authority",
        "selector_deployment_authority",
        "adapter_mutation_authority",
        "production_prompt_mutation_authority",
        "production_math_mode_claim",
    ]:
        assert receipt[key] is False
