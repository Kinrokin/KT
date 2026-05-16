from __future__ import annotations

import pytest

from tools.operator import highway_common as highway


def test_comparative_proof_guard_allows_prep_without_superiority_claim(tmp_path):
    receipt = highway.comparative_proof_guard(superiority_claimed=False, output_root=tmp_path)
    assert receipt["initial_status"] == "COMPARATIVE_PROOF_PREPARED_NOT_CLAIMED"
    assert receipt["claim_allowed"] is True


def test_comparative_proof_guard_rejects_superiority_without_receipts(tmp_path):
    with pytest.raises(highway.HighwayFailure) as excinfo:
        highway.comparative_proof_guard(superiority_claimed=True, comparative_receipts_present=False, output_root=tmp_path)
    assert excinfo.value.code == "HIGHWAY_COMPARATIVE_CLAIM_UNSUPPORTED"
