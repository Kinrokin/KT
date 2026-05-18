from __future__ import annotations

from tools.operator import highway_common as highway


def test_regulated_lane_requires_claim_limiter_and_evidence_manifest(tmp_path):
    receipt = highway.regulated_lane_guard({"commercial_claim_limiter": True, "evidence_manifest": True}, tmp_path)
    assert receipt["regulated_work_allowed_as_prep_only"] is True
    assert receipt["unsupported_legal_or_compliance_posture"] is False


def test_regulated_lane_rejects_missing_claim_limiter_or_evidence_manifest(tmp_path):
    receipt = highway.regulated_lane_guard({}, tmp_path)
    assert receipt["regulated_work_allowed_as_prep_only"] is False
    assert receipt["status"] == "FAIL_CLOSED"
