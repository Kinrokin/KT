from __future__ import annotations

import pytest

from tools.operator import highway_common as highway


def test_commercial_claim_guard_accepts_bounded_claims(tmp_path):
    receipt = highway.commercial_claim_guard(["Highway pathway system is prep-only."], tmp_path)
    assert receipt["status"] == "PASS"


def test_commercial_claim_guard_rejects_unsupported_compliance_claims(tmp_path):
    with pytest.raises(highway.HighwayFailure) as excinfo:
        highway.commercial_claim_guard(["KT is SOC 2 certified."], tmp_path)
    assert excinfo.value.code == "HIGHWAY_COMMERCIAL_OVERCLAIM"
