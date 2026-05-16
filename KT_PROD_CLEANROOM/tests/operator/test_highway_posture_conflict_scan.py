from __future__ import annotations

import pytest

from tools.operator import highway_common as highway


def test_posture_conflict_scanner_passes_current_prep_only_claims(tmp_path):
    receipt = highway.posture_conflict_scan(["HIGHWAY_PREP_ONLY"], tmp_path)
    assert receipt["posture_conflict_count"] == 0
    assert receipt["status"] == "PASS"


def test_posture_conflict_scanner_rejects_stronger_than_truth_claims(tmp_path):
    with pytest.raises(highway.HighwayFailure) as excinfo:
        highway.posture_conflict_scan(["HIGHWAY_CANONICAL_ACTIVE"], tmp_path)
    assert excinfo.value.code == "HIGHWAY_POSTURE_CONFLICT"
