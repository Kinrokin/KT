from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def test_v17_4_result_review_binds_measured_run_without_promotion():
    receipt = load("reports/v17_4_result_review_receipt.json")
    import_receipt = load("reports/v17_4_measured_artifact_import_receipt.json")
    assert receipt["real_measured_run"] is True
    assert receipt["runtime_stability_repaired"] is True
    assert receipt["tied_feature_bound_route"] is True
    assert receipt["oracle_gap_closed"] is False
    assert receipt["runtime_authority"] is False
    assert receipt["promotion_authority"] is False
    assert import_receipt["synthetic_or_aggregate_rows_used"] is False
    assert import_receipt["rows"] == 260
    assert import_receipt["assessment_zip_sha256"] == "2187c8ace46c3c5da9c7cf7debf79ebfc6eb38566ea8c589750977694a975699"
