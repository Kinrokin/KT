from __future__ import annotations

from tools.operator import highway_common as highway


def test_rollback_plan_exists_before_canonical_promotion(tmp_path):
    receipt = highway.rollback_plan(tmp_path)
    assert receipt["rollback_required_for_canonical_promotion"] is True
    assert receipt["canonical_change_present"] is False
