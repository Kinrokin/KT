from tests.v17_7_3_authority_utils import authority_report


def test_v1772_risk_update_binds_old_and_new_risk_values() -> None:
    receipt = authority_report("v17_7_3_v1772_risk_update_receipt.json")
    assert receipt["status"] == "PASS"
    assert receipt["old_pfail"] == 0.9895594256814249
    assert receipt["new_pfail_proxy"] == 0.1375
    assert receipt["pfail_delta"] < 0
    assert receipt["old_dgs"] == -4.250771105439233
