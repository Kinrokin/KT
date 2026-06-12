from __future__ import annotations

from pathlib import Path

from scripts import ktbud100_common as bud


def test_bud25_assessment_import_receipt_binds_expected_zip() -> None:
    receipt = bud.import_bud25_assessment()

    assert receipt["status"] == "PASS"
    assert receipt["assessment_sha256"] == bud.BUD25_EXPECTED_SHA256
    assert receipt["row_count"] == 25
    assert receipt["oracle_diagnostic_score"] == 1.0
    assert receipt["budget_metrics"]["cot_512_accuracy"] == 0.92
    assert Path("reports/bud25_assessment_import_receipt.json").exists()
