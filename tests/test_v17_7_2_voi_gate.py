from tests.v17_7_2_utils import assert_no_authority, read_json


def test_v17_7_2_voi_gate_demands_data() -> None:
    receipt = read_json("reports/v17_7_2_voi_gate.json")
    assert receipt["value_of_information_positive"] is True
    assert receipt["voi_decision"] == "ACQUIRE_MORE_TARGETED_EVIDENCE"
    assert receipt["status"] == "VOI_DEMANDS_DATA"
    assert_no_authority(receipt)
