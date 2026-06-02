from tests.v17_7_3_utils import assert_no_authority, packet_names, read_json


def test_v17_7_3_authority_split_and_packet_are_evidence_only() -> None:
    receipt = read_json("reports/v17_7_3_authority_split_receipt.json")
    names = packet_names("packets/ktv1773_evidence_acquisition_e2e_v1.zip")
    assert receipt["evidence_packet_authority"] is True
    assert "KTV1773_MICRO_FURNACE_MASTER_RUNNER.py" in names
    assert "runtime_inputs/targeted_boundary_row_manifest.json" in names
    assert_no_authority(receipt)
