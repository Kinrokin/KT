from tests.v17_7_3_authority_utils import authority_report


def test_pfail_proxy_uniformity_is_audited() -> None:
    uniformity = authority_report("v17_7_3_pfail_proxy_uniformity_receipt.json")
    audit = authority_report("v17_7_3_pfail_silent_failure_audit.json")
    assert uniformity["status"] == "PASS"
    assert uniformity["pfail_proxy"] == 0.1375
    assert uniformity["flat_proxy_constant_detected"] is True
    assert audit["new_pfail_proxy"] == 0.1375
