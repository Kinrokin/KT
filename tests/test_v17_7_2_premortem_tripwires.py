from tests.v17_7_2_utils import assert_no_authority, read_json


def test_v17_7_2_premortem_tripwires_are_compiled() -> None:
    receipt = read_json("reports/v17_7_2_premortem_compilation_receipt.json")
    assert receipt["tripwire_count"] >= 3
    assert receipt["future_unpredicted_failure_block"] == "KTG3FULL_V17_7_3_BLOCKED__MHM_BLIND_SPOT"
    assert_no_authority(receipt)
