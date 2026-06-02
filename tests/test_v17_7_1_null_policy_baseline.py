from __future__ import annotations

from pathlib import Path

from scripts.v17_7_1_mhm_common import read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_1_null_policy_baseline_classifies_plus_one() -> None:
    null = read_json(ROOT / "reports" / "v17_7_1_null_policy_baseline.json")
    random_baseline = read_json(ROOT / "reports" / "v17_7_1_random_policy_search_baseline.json")
    permutation = read_json(ROOT / "reports" / "v17_7_1_permutation_test_receipt.json")
    assert null["candidate_score"] == 162
    assert null["classification"] == "SCAR_TISSUE_DIAGNOSTIC_ONLY"
    assert random_baseline["candidate_status"] == "SCAR_TISSUE_DIAGNOSTIC_ONLY"
    assert permutation["permutation_pass"] is False
