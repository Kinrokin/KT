from __future__ import annotations

import json
from pathlib import Path


def test_bud100_claim_ceiling_and_next_move() -> None:
    summary = json.loads(Path("reports/bud100_review_builder_summary.json").read_text(encoding="utf-8"))
    claim = json.loads(Path("reports/bud100_claim_boundary_receipt.json").read_text(encoding="utf-8"))

    assert summary["outcome"] == (
        "KT_BUD100_ASSESSMENT_IMPORTED__TOKEN_BUDGET_CONFIRMED__"
        "ADAPTIVE_MONITOR_V2_REPAIR_NEXT__CLAIM_CEILING_PRESERVED"
    )
    assert summary["runtime_authority"] is False
    assert summary["dataset_generation_authority"] is False
    assert summary["training_authority"] is False
    assert summary["promotion_authority"] is False
    assert summary["adapter_mutation_authority"] is False
    assert summary["production_prompt_mutation_authority"] is False
    assert summary["next_lawful_move"] == "AUTHOR_BUD100_ADAPTIVE_MONITOR_V2_POLICY_REPAIR_NO_PRODUCTION_MUTATION"
    assert claim["claim_ceiling_preserved"] is True
