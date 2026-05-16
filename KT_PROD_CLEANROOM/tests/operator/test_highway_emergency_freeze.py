from __future__ import annotations

from tools.operator import highway_common as highway


def test_emergency_lane_can_freeze_but_cannot_authorize_bypass(tmp_path):
    receipt = highway.emergency_freeze("TRUTH_LOCK_DRIFT", tmp_path)
    assert receipt["freeze_allowed"] is True
    assert receipt["authority_bypass_authorized"] is False
    assert receipt["truth_lock_bypass_authorized"] is False
