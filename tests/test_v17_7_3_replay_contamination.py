from tests.v17_7_3_authority_utils import authority_report


def test_replay_contamination_scan_blocks_placeholder_laundering() -> None:
    scan = authority_report("v17_7_3_replay_contamination_scan.json")
    boundary = authority_report("v17_7_3_provenance_claim_boundary_receipt.json")
    assert scan["status"] == "PASS"
    assert scan["forbidden_statuses_present"] == []
    assert scan["oracle_correctness_used_as_input_feature"] is False
    assert "learned-router superiority" in boundary["disallowed_claims"]
