from tests.v17_7_3_utils import assert_no_authority, read_json


def test_v17_7_3_preregistration_is_locked_before_acquisition() -> None:
    protocol = read_json("admission/v17_7_3_pre_registered_acquisition_protocol.json")
    receipt = read_json("reports/v17_7_3_acquisition_preregistration_receipt.json")
    assert protocol["protocol_locked"] is True
    assert protocol["post_hoc_changes_allowed"] is False
    assert protocol["selection_method"] == "expected_information_gain"
    assert receipt["post_hoc_acquisition"] is False
    assert_no_authority(protocol)
    assert_no_authority(receipt)
