from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_court_v2_declares_general_rule_not_row_specific_exception() -> None:
    audit = json.loads((ROOT / "reports/ktstoprt_eos_adjudication_audit.json").read_text(encoding="utf-8-sig"))
    mutation = json.loads((ROOT / "reports/ktstoprt_court_mutation_receipt.json").read_text(encoding="utf-8-sig"))
    assert audit["no_row_specific_logic"] is True
    assert mutation["no_row_specific_logic"] is True
    assert "Strip terminal EOS/PAD symmetrically" in audit["terminal_eos_or_pad_normalization_rule"]
