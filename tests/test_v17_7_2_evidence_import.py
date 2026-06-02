from tests.v17_7_2_utils import assert_no_authority, read_json


def test_v17_7_2_imports_v1771_evidence_from_rows() -> None:
    receipt = read_json("reports/v17_7_2_v1771_evidence_import_receipt.json")
    assert receipt["status"] == "PASS"
    assert receipt["row_count"] == 260
    assert receipt["imported_candidate_status"] == "SCAR_TISSUE_DIAGNOSTIC_ONLY"
    assert_no_authority(receipt)
