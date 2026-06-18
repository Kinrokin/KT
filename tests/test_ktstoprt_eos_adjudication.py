from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_eos_adjudication_reconciles_only_terminal_special_mismatches() -> None:
    receipt = json.loads((ROOT / "reports/ktstoprt_eos_adjudication_audit.json").read_text(encoding="utf-8-sig"))
    assert receipt["status"] == "PASS_EOS_AWARE_RECONCILIATION"
    assert receipt["official_prefix_equal_count"] == 8
    assert receipt["court_v2_prefix_equal_count"] == 10
    assert receipt["natural_eos_rows_reconciled"] == ["gsm8k_test_340", "gsm8k_test_368"]
    assert receipt["no_row_specific_logic"] is True
