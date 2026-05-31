from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_v18_coalition_atlas_has_candidate_families_and_no_authority():
    atlas = json.loads((ROOT / "capability/capability_habitat_topology.json").read_text(encoding="utf-8"))
    families = atlas["families"]
    assert len(families) == 11
    assert {family["family_id"] for family in families} >= {
        "quantitative_reasoning_candidate",
        "hat_salvage_candidate",
        "route_regret_policy_candidate",
        "audit_proof_candidate",
    }
    for family in families:
        assert family["runtime_authority"] is False
        assert family["promotion_authority"] is False
        assert family["claim_scope"] == "LAB_PREP_OR_SHADOW_ONLY"
    assert atlas["claim_ceiling_preserved"] is True
