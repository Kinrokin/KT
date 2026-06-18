from __future__ import annotations

import json
from pathlib import Path


AUTHORITY_FIELDS = [
    "runtime_authority",
    "dataset_generation_authority",
    "training_authority",
    "promotion_authority",
    "selector_deployment_authority",
    "adapter_mutation_authority",
    "production_prompt_mutation_authority",
    "production_math_mode_claim",
]


def test_ktstoprt_claim_ceiling_and_authorities() -> None:
    for path in [
        "reports/ktstoprt_next_runtime_packet_decision.json",
        "reports/ktstoprt_claim_boundary_receipt.json",
        "reports/ktstoprt_scoped_authority_receipt.json",
    ]:
        data = json.loads(Path(path).read_text())
        assert data["claim_ceiling_status"] == "PRESERVED"
        for field in AUTHORITY_FIELDS:
            assert data[field] is False
    scoped = json.loads(Path("reports/ktstoprt_scoped_authority_receipt.json").read_text())
    assert scoped["sandbox_inference_authority"] is True
