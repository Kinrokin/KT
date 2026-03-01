from __future__ import annotations

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_ = bootstrap_syspath()

from tools.verification.fl3_meta_evaluator import assert_law_amendment_attestation_sufficient  # noqa: E402
from tools.verification.fl3_validators import FL3ValidationError  # noqa: E402


def test_canonical_lane_rejects_simulated_law_amendment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KT_CANONICAL_LANE", "1")
    with pytest.raises(FL3ValidationError):
        assert_law_amendment_attestation_sufficient(
            amendment={"schema_id": "kt.law_amendment.v2", "attestation_mode": "SIMULATED", "signoffs": []}
        )
