import json
from pathlib import Path

from ktpareto_helpers import ensure_ktpareto_built


ROOT = Path(__file__).resolve().parents[1]


def test_ktpareto_row_policy_is_clean_non_overlap_slice():
    ensure_ktpareto_built()
    row_policy = json.loads((ROOT / "reports" / "ktpareto_row_policy_receipt.json").read_text())
    assert row_policy["dataset"] == "openai/gsm8k"
    assert row_policy["split"] == "test"
    assert row_policy["slice_start"] == 325
    assert row_policy["slice_end"] == 425
    assert row_policy["row_count"] == 100
    assert row_policy["overlap_with_bud25"] is False
    assert row_policy["overlap_with_bud100"] is False
    assert row_policy["overlap_with_kt512base"] is False
