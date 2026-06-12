from __future__ import annotations

from scripts import ktbud100_common as bud


def test_bud25_load_falls_back_to_committed_receipt_when_zip_absent(monkeypatch) -> None:
    monkeypatch.setattr(bud, "find_bud25_zip", lambda: None)

    data = bud.load_bud25()

    assert data["source"]["status"] == "COMMITTED_RECEIPT_FALLBACK"
    assert data["source"]["sha256"] == bud.BUD25_EXPECTED_SHA256
    assert data["final_summary"]["sample_count"] == 25
    assert data["final_summary"]["cot_512_accuracy"] == 0.92


def test_bud25_assessment_import_receipt_binds_expected_zip() -> None:
    receipt = bud.read_json(bud.REPORTS / "bud25_assessment_import_receipt.json")

    assert receipt["status"] == "PASS"
    assert receipt["assessment_sha256"] == bud.BUD25_EXPECTED_SHA256
    assert receipt["row_count"] == 25
    assert receipt["oracle_diagnostic_score"] == 1.0
    assert receipt["budget_metrics"]["cot_512_accuracy"] == 0.92
