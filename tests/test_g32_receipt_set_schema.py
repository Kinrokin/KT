from __future__ import annotations

from g32_test_utils import load_json, required_schema_fields


def test_do_not_train_receipt_set_schema_and_receipt_are_present() -> None:
    required = required_schema_fields("schemas/kt.do_not_train_receipt_set.schema.json")
    receipt = load_json("reports/g32_do_not_train_receipt_set.json")

    assert required.issubset(receipt)
    assert receipt["claim_ceiling_preserved"] is True
    assert isinstance(receipt["receipts"], list)
