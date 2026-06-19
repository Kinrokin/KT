import json
from pathlib import Path


def test_v2_claim_ceiling_and_authority_boundaries_preserved():
    receipt = json.loads(Path("reports/stop300_v2_packet_validation_receipt.json").read_text(encoding="utf-8-sig"))
    assert receipt["claim_ceiling_status"] == "PRESERVED"
    assert receipt["sandbox_inference_authority"] is True
    for key in [
        "shadow_runtime_authority",
        "runtime_authority",
        "dataset_generation_authority",
        "training_authority",
        "promotion_authority",
        "selector_deployment_authority",
        "adapter_mutation_authority",
        "production_prompt_mutation_authority",
        "production_math_mode_claim",
    ]:
        assert receipt[key] is False
