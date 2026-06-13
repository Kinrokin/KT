from __future__ import annotations

import json
from pathlib import Path


def test_bud100_monitor_v2_design_is_design_only() -> None:
    policy = json.loads(Path("admission/bud100_adaptive_monitor_v2_candidate_policy.json").read_text(encoding="utf-8"))
    receipt = json.loads(Path("reports/bud100_adaptive_monitor_v2_design_receipt.json").read_text(encoding="utf-8"))

    assert policy["policy_id"] == "BUDGET_MONITOR_MATH_V2_CANDIDATE"
    assert policy["status"] == "DESIGN_ONLY_NO_PRODUCTION_AUTHORITY"
    assert policy["multi_step_math"]["default_budget"] == 512
    assert policy["multi_step_math"]["stop_on_final_marker"] is True
    assert policy["authority"]["runtime_authority"] is False
    assert policy["authority"]["training_authority"] is False
    assert receipt["status"] == "PASS_DESIGN_ONLY"
    assert receipt["claim_ceiling_preserved"] is True
