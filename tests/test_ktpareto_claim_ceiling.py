import json
from pathlib import Path

from ktpareto_helpers import ensure_ktpareto_built


ROOT = Path(__file__).resolve().parents[1]


def test_ktpareto_claim_boundary_preserves_ceiling():
    ensure_ktpareto_built()
    receipt = json.loads((ROOT / "reports" / "ktpareto_claim_boundary_receipt.json").read_text())
    assert receipt["status"] == "PASS"
    assert receipt["claim_ceiling_preserved"] is True
    assert receipt["runtime_authority"] is False
    assert receipt["training_authority"] is False
    assert receipt["promotion_authority"] is False
    assert receipt["adapter_mutation_authority"] is False
    assert receipt["production_prompt_mutation_authority"] is False
    assert receipt["router_superiority_claim"] is False
    assert receipt["frontier_claim"] is False
