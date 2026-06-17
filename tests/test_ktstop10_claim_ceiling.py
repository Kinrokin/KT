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


def test_ktstop10_claim_ceiling_and_authorities_false() -> None:
    for path in [
        "reports/ktstop10_runtime_packet_decision.json",
        "reports/ktstop10_claim_boundary_receipt.json",
        "reports/ktstop10_builder_summary.json",
    ]:
        data = json.loads(Path(path).read_text())
        assert data["claim_ceiling_status"] == "PRESERVED"
        for field in AUTHORITY_FIELDS:
            assert data[field] is False
