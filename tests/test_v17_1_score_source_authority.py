from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_score_source_authority_is_row_level_recomputation():
    receipt = json.loads((ROOT / "reports/v17_1_score_source_authority_receipt.json").read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["authoritative_source"] == "row_level_recomputation"
    assert receipt["lower_sources_may_not_outrun_rows"] is True
