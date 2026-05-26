from __future__ import annotations

from g32_test_utils import load_json


def test_cross_domain_concepts_are_artifactized_not_inspiration_soup() -> None:
    registry = load_json("research/cross_domain_concept_registry.json")
    mapped = load_json("research/domain_to_kt_artifact_map.json")
    ledger = load_json("research/cross_domain_source_evidence_ledger.json")

    assert registry["schema_id"] == "kt.cross_domain_concept_registry.v1"
    assert len(registry["concepts"]) >= 10
    assert all(row["proposed_artifact"] and row["metric"] and row["quarantine_rule"] for row in mapped["rows"])
    assert all(source["claim_ceiling_effect"] == "NONE" for source in ledger["sources"])
