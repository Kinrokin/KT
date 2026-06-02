from tests.v17_7_3_utils import assert_no_authority, read_json


def test_v17_7_3_imports_v1772_active_learning_evidence() -> None:
    receipt = read_json("reports/v17_7_3_v1772_evidence_import_receipt.json")
    assert receipt["status"] == "PASS"
    assert receipt["row_count"] == 260
    assert receipt["decision_row_count"] == 260
    assert receipt["imported_pfail"] == 0.9895594256814249
    assert receipt["imported_dgs"] == -4.250771105439233
    assert_no_authority(receipt)
