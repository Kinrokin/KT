from __future__ import annotations

import json
from pathlib import Path


def test_bud100_row_policy_autopsy_counts() -> None:
    autopsy = json.loads(Path("reports/bud100_row_policy_autopsy.json").read_text(encoding="utf-8"))
    delta = json.loads(Path("reports/bud100_adaptive_vs_cot512_delta_matrix.json").read_text(encoding="utf-8"))

    assert autopsy["status"] == "PASS"
    assert autopsy["row_count"] == 100
    assert autopsy["answer_only_sufficient_count"] == 25
    assert autopsy["cot256_sufficient_count"] == 71
    assert autopsy["cot512_required_count"] == 20
    assert autopsy["monitor_policy_failure_count"] == 2
    assert autopsy["monitor_recovery_count"] == 0
    assert autopsy["capability_gap_count"] == 9
    assert autopsy["token_starvation_count"] == 89
    assert autopsy["extension_harm_or_insufficiency_count"] == 5
    assert autopsy["hard_ceiling_failure_count"] == 2
    assert autopsy["overthink_risk_count"] == 0
    assert delta["adaptive_monitor_v1_verdict"] == "CONFIRMED_BUT_NOT_COST_OPTIMAL"
