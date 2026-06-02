from tests.v17_7_3_utils import assert_no_authority, read_json


def test_v17_7_3_oracle_labels_are_independent_and_not_features() -> None:
    contract = read_json("admission/v17_7_3_oracle_labeling_contract.json")
    receipt = read_json("reports/v17_7_3_oracle_label_integrity_receipt.json")
    assert contract["oracle_labels_are_posthoc_only"] is True
    assert contract["oracle_correctness_used_as_input_feature"] is False
    assert contract["policy_design_independent_from_labels"] is True
    assert receipt["label_contamination_blocked"] is True
    assert_no_authority(contract)
    assert_no_authority(receipt)
