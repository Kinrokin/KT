from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_prefix_equivalence_v2_is_new_court_not_old_receipt_rewrite() -> None:
    receipt = json.loads((ROOT / "reports/ktstoprt_prefix_equivalence_v2.json").read_text(encoding="utf-8-sig"))
    assert receipt["status"] == "PASS_10_OF_10_ORIGINAL_TOKEN_IDS_WITH_SYMMETRIC_EOS_NORMALIZATION"
    assert receipt["official_receipt_status"] == "PRESERVED_FAILED_8_OF_10"
    assert receipt["court_v2_status"] == "RECONCILED_PASS_10_OF_10"
    assert receipt["court_v2_prefix_equal_count"] == receipt["row_count"] == 10
