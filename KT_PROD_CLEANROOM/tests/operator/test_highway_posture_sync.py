from __future__ import annotations

from tools.operator import highway_common as highway


def test_posture_sync_derives_prep_only_from_authority_gate(tmp_path):
    receipt = highway.posture_sync(tmp_path)
    assert receipt["posture"] == "HIGHWAY_PREP_ONLY"
    assert receipt["strongest_supported_posture"] == "HIGHWAY_PREP_ONLY"
    assert receipt["truth_basis"]["activation_allowed"] is False
