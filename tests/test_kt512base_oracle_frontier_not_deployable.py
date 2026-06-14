from __future__ import annotations

import json
from pathlib import Path


def load_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def test_kt512base_oracle_frontier_is_hindsight_only_not_deployable() -> None:
    frontier = load_json("reports/kt512base_cheapest_correct_oracle_frontier.json")

    assert frontier["authority"] == "HINDSIGHT_ONLY_NOT_DEPLOYABLE"
    assert frontier["runtime_selector_claim"] == "BLOCKED"
    assert frontier["must_not_claim_deployable_selector"] is True
    assert frontier["hindsight_oracle_correct"] == 186
    assert frontier["fixed512_correct"] == 184
    assert frontier["claim_ceiling_preserved"] is True


def test_kt512base_process_verifier_is_design_only() -> None:
    verifier = load_json("reports/kt512base_process_verifier_seed_plan.json")
    segmentation = load_json("reports/kt512base_step_segmentation_policy.json")

    assert verifier["status"] == "DESIGN_ONLY_REQUIRES_SEPARATE_VERIFIER_VALIDATION_LANE"
    assert verifier["may_score_production_rows"] is False
    assert verifier["may_authorize_training"] is False
    assert segmentation["status"] == "DESIGN_ONLY"
    assert segmentation["consistency_graph_required"] is True
    assert segmentation["independent_step_labels_only"] is False
