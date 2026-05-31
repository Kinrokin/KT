from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def test_evidence_sidecars_bind_v17_packet_and_claim_ceiling():
    registry = read_json("evidence/evidence_object_registry.json")
    lineage = read_json("evidence/run_lineage_graph.json")
    deps = read_json("evidence/receipt_dependency_graph.json")
    claim_map = read_json("evidence/claim_to_evidence_map.json")
    hf_index = read_json("evidence/hf_artifact_index.json")

    assert registry["packet_sha256"]
    assert any(obj["path"] == "reports/v17_canary_packet_readiness_receipt.json" for obj in registry["objects"])
    assert {"from": "V16 shadow route-value replay", "to": "V17 canary route-value packet"} in lineage["lineage"]
    assert "reports/v17_canary_packet_readiness_receipt.json" in deps["dependencies"]
    assert claim_map["claims"][0]["tier"] == "PREP_ONLY"
    assert hf_index["artifacts"] == []
    assert all(obj.get("claim_ceiling_preserved") is True for obj in [registry, lineage, deps, claim_map, hf_index])
