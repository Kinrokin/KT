import json
from pathlib import Path

from ktpareto_helpers import ensure_ktpareto_built


ROOT = Path(__file__).resolve().parents[1]


def test_ktpareto_claim_bounds_cover_all_arms_and_block_promotion():
    ensure_ktpareto_built()
    bounds = json.loads((ROOT / "reports" / "ktpareto_per_arm_claim_bounds.json").read_text())
    arm_ids = {row["arm_id"] for row in bounds["rows"]}
    assert arm_ids == {
        "A0_COT_96_FIXED",
        "A1_COT_192_FIXED",
        "A2_COT_256_FIXED",
        "A3_COT_320_FIXED",
        "A4_COT_384_FIXED",
        "A5_COT_448_FIXED",
        "A6_COT_512_FIXED_CONTROL",
        "A7_COT_640_FIXED_SENTINEL",
        "A8_ANSWER_ONLY_NO_COT",
        "A9_ORACLE_DIAGNOSTIC_PER_ARM",
    }
    assert all(row["promotion_authority"] is False for row in bounds["rows"])
    assert all(row["runtime_selector_deployment"] is False for row in bounds["rows"])
