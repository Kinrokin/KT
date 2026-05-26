from __future__ import annotations

from g32_test_utils import load_json


def test_repairability_classifier_emits_causal_owner_clusters() -> None:
    receipt = load_json("reports/g32_training_decision_receipt.json")
    decisions = receipt["decisions"]
    owners = {row["counterfactual_owner"] for row in decisions}
    cluster_ids = [row["cluster_id"] for row in decisions]

    assert "ADAPTER_OWNED" in owners
    assert "ROUTE_OWNED" in owners
    assert all(len(cluster_id.split("::")) == 5 for cluster_id in cluster_ids)
    assert all(row["cluster_id"].startswith(row["counterfactual_owner"] + "::") for row in decisions)
