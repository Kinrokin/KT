from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_v17_5_result_review_binds_minimum_pass_without_promotion():
    receipt = json.loads((ROOT / "reports/v17_5_result_review_receipt.json").read_text(encoding="utf-8"))
    minimum = json.loads((ROOT / "reports/v17_5_scientific_minimum_pass_receipt.json").read_text(encoding="utf-8"))
    do_not_promote = json.loads((ROOT / "reports/v17_5_do_not_promote_receipt.json").read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["scientific_result"] == "MINIMUM_PASS_NOT_BREAKTHROUGH"
    assert minimum["minimum_pass"] is True
    assert minimum["breakthrough_pass"] is False
    assert do_not_promote["route_promotion_authorized"] is False
    assert do_not_promote["adapter_promotion_authorized"] is False
    assert do_not_promote["v18_runtime_authorized"] is False
