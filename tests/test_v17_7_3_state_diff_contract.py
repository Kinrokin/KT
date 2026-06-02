from tests.v17_7_3_utils import assert_no_authority, read_json


def test_v17_7_3_state_diff_contract_blocks_trace_only_eval() -> None:
    contract = read_json("admission/v17_7_3_state_diff_evaluation_contract.json")
    receipt = read_json("reports/v17_7_3_state_diff_contract_receipt.json")
    assert contract["state_diff_required_for_agentic_rows"] is True
    assert contract["semantic_trace_matching_replaces_state_diff"] is False
    assert receipt["state_diff_rows"] > 0
    assert_no_authority(contract)
    assert_no_authority(receipt)
