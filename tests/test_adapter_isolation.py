from __future__ import annotations

from g32_test_utils import load_json


def test_adapter_isolation_contract_blocks_unproven_rankings() -> None:
    receipt = load_json("reports/adapter_isolation_contract_receipt.json")

    assert receipt["schema_id"] == "kt.adapter_isolation_receipt.v1"
    assert receipt["base_model_reloaded"] is True
    assert receipt["peft_wrappers_removed"] is True
    assert receipt["cuda_cleanup_before_arm"] is True
    assert receipt["cuda_cleanup_after_arm"] is True
    assert receipt["status"] == "SPEC_READY_RUNTIME_MEASUREMENT_REQUIRED"
