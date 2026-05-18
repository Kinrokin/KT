from __future__ import annotations

from tools.operator import highway_common as highway


def test_incident_receipt_supports_required_incident_classes(tmp_path):
    receipt = highway.incident_receipt("COMMERCIAL_OVERCLAIM", tmp_path)
    assert "COMMERCIAL_OVERCLAIM" in receipt["incident_classes_supported"]
    assert "UNAUTHORIZED_FP0_PROMOTION" in receipt["incident_classes_supported"]
