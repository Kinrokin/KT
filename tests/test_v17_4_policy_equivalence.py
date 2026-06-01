from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_policy_equivalence_identifies_v16_v17_canary_equivalence_but_not_feature_bound():
    receipt = json.loads((ROOT / "reports/v17_4_policy_equivalence_receipt.json").read_text(encoding="utf-8"))
    overlap = receipt["jaccard_overlap_by_policy_pair"]
    assert receipt["policy_equivalence_determined_from_rows"] is True
    assert overlap["V16_shadow_replay_baseline__V17_canary_policy"] == 1.0
    assert overlap["V17_canary_policy__feature_bound_route"] < 1.0
    assert receipt["feature_bound_equivalent"] is False
    assert receipt["same_score_different_rows"] is True
