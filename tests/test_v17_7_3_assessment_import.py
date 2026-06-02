from tests.v17_7_3_authority_utils import assert_no_authority, authority_report


def test_v17_7_3_imports_measured_arm_assessment_zip() -> None:
    receipt = authority_report("v17_7_3_assessment_import_receipt.json")
    assert receipt["status"] == "PASS"
    assert receipt["row_readable"] is True
    assert receipt["required_members_present"] is True
    assert receipt["defects"] == []
    assert receipt["assessment_sha256"]
    assert_no_authority(receipt)


def test_v17_7_3_assessment_manifest_binds_row_artifacts() -> None:
    manifest = authority_report("v17_7_3_assessment_manifest_receipt.json")
    assert manifest["row_count"] == 400
    assert manifest["arm_rows"] == 2000
    assert "benchmark_predictions.jsonl" in manifest["member_names"]
    assert "arm_result_matrix.jsonl" in manifest["member_names"]
    assert manifest["member_hashes"]["benchmark_predictions.jsonl"]
