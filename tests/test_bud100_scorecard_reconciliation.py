from __future__ import annotations

import json
from pathlib import Path


def test_bud100_scorecard_reconciliation() -> None:
    curve = json.loads(Path("reports/bud100_budget_curve_scorecard.json").read_text(encoding="utf-8"))
    reconciliation = json.loads(Path("reports/bud100_scorecard_reconciliation.json").read_text(encoding="utf-8"))

    assert curve["status"] == "PASS"
    assert curve["cot_96_accuracy"] == 0.02
    assert curve["cot_256_accuracy"] == 0.71
    assert curve["cot_512_accuracy"] == 0.91
    assert curve["answer_only_96_accuracy"] == 0.25
    assert curve["adaptive_monitor_accuracy"] == 0.89
    assert curve["oracle_diagnostic_score"] == 1.0
    assert curve["token_budget_sensitivity_confirmed"] is True
    assert curve["adaptive_monitor_confirmation_supported"] is True
    assert curve["adaptive_monitor_cost_optimal"] is False
    assert curve["best_measured_arm"] == "A2_COT_512_FIXED"
    assert reconciliation["scorecard_mismatches"] == []
