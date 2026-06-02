from tests.v17_7_2_utils import read_json


def test_v17_7_3_unpredicted_failure_has_block_label() -> None:
    receipt = read_json("reports/v17_7_2_policy_premortem.json")
    labels = {row["future_block_label"] for row in receipt["tripwires"]}
    assert "KTG3FULL_V17_7_3_BLOCKED__MHM_BLIND_SPOT" in labels
