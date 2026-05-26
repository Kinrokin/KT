from __future__ import annotations

from g32_test_utils import load_json


def test_long_horizon_crucible_is_parked_as_scaffold_not_fake_pass() -> None:
    receipt = load_json("reports/long_horizon_state_tracking_receipt.json")

    assert receipt["status"] == "SCAFFOLD_EMITTED_NOT_EARNED"
    assert receipt["promotion_eligible"] is False
    assert receipt["requires_followup_measurement"] is True
    assert receipt["mini_crucible"] == ["benchmark_miss", "pressure_item", "repair_corpus", "adapter_delta", "replay", "claim_compiler_summary"]
