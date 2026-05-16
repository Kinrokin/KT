from __future__ import annotations

from tools.operator import highway_common as highway


def test_promotion_gate_rejects_prep_only_to_canonical_jump(tmp_path):
    receipt = highway.promotion_gate("PREP_ONLY", "CANONICAL_ACTIVE", tmp_path)
    assert receipt["promotion_allowed"] is False
    assert "PROMOTION_LADDER_OR_AUTHORITY_NOT_SATISFIED" in receipt["blockers"]


def test_promotion_gate_requires_ordered_ladder(tmp_path):
    receipt = highway.promotion_gate("PREP_ONLY", "SHADOW_ONLY", tmp_path)
    assert receipt["promotion_allowed"] is True
    assert receipt["promotion_ladder"] == list(highway.PROMOTION_LADDER)
