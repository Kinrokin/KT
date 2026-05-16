from __future__ import annotations

import pytest

from tools.operator import highway_common as highway


def test_trust_zone_validator_accepts_explicit_justified_exclusion(tmp_path):
    receipt = highway.trust_zone_validate({"exclusions": [{"path": "archive/", "justification": "historical"}]}, tmp_path)
    assert receipt["status"] == "PASS"


def test_trust_zone_validator_rejects_silent_exclusions(tmp_path):
    with pytest.raises(highway.HighwayFailure) as excinfo:
        highway.trust_zone_validate({"silent_exclusions": ["bad/path"]}, tmp_path)
    assert excinfo.value.code == "HIGHWAY_TRUST_ZONE_CONFLICT"
