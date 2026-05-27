from __future__ import annotations

from g32_test_utils import load_json, required_schema_fields


def test_v12_evidence_import_discloses_raw_row_absence_and_preserves_claim_ceiling() -> None:
    receipt = load_json("reports/v12_evidence_import_receipt.json")

    assert receipt["schema_id"] == "kt.v12_evidence_import_receipt.v1"
    assert receipt["benchmark_predictions_rows"] == 200
    assert receipt["raw_prediction_rows_present"] is False
    assert "RAW_ROWS_NOT_PRESENT" in receipt["import_status"]
    assert receipt["base_raw_correct_count"] == 111
    assert receipt["base_raw_gsm8k_correct_count"] == 2
    assert receipt["formal_math_adapter_gsm8k_correct_count"] == 13
    assert receipt["claim_ceiling_preserved"] is True


def test_v12_evidence_import_schema_has_required_gate_fields() -> None:
    required = required_schema_fields("schemas/kt.v12_evidence_import_receipt.schema.json")

    assert {
        "schema_id",
        "source_hf_url_or_artifact_path",
        "benchmark_predictions_rows",
        "import_status",
        "claim_ceiling_preserved",
    } <= required
