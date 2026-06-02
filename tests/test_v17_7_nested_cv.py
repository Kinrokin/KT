from __future__ import annotations

from pathlib import Path

from scripts.v17_7_1_mhm_common import read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_nested_cv_keeps_overfit_blocker() -> None:
    nested = read_json(ROOT / "reports" / "v17_7_1_nested_cv_receipt.json")
    dataset = read_json(ROOT / "reports" / "v17_7_dataset_failure_matrix.json")
    slices = read_json(ROOT / "reports" / "v17_7_slice_failure_matrix.json")
    assert nested["status"] == "FAIL"
    assert dataset["status"] == "FAIL"
    assert slices["status"] == "FAIL"
