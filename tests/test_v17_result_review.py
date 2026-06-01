from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_v17_result_review_confesses_failed_canary_without_promotion():
    review = json.loads((ROOT / "reports/v17_result_review_receipt.json").read_text(encoding="utf-8"))
    confession = json.loads((ROOT / "reports/v17_failure_confession_receipt.json").read_text(encoding="utf-8"))
    assert review["status"] == "FAILURE_CONFESSED"
    assert review["measured_facts"]["canary_policy_correct"] == 153
    assert review["measured_facts"]["feature_bound_correct"] == 159
    assert confession["v17_v1_1_claimable"] is False
    assert confession["v18_authorized"] is False
    assert confession["route_promotion_authorized"] is False
    assert confession["learned_router_superiority_authorized"] is False
