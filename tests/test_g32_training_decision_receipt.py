from __future__ import annotations

from g32_test_utils import load_json


def test_training_decision_receipt_authorizes_only_evidence_backed_training() -> None:
    receipt = load_json("reports/g32_training_decision_receipt.json")
    decisions = receipt["decisions"]
    train_decisions = [row for row in decisions if row["training_decision"] in {"TRAIN_ADAPTER", "TRAIN_ROUTER"}]

    assert receipt["adapter_owned_alone_authorizes_training"] is False
    assert train_decisions
    assert all(row["minimum_viable_signal_pass"] is True for row in train_decisions)
    assert all(row["claim_ceiling_preserved"] is True for row in decisions)
