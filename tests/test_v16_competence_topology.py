from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_v16_competence_topology_emits_route_nodes_and_dataset_slices():
    topology = json.loads((ROOT / "admission/v16_capability_habitat_topology.json").read_text(encoding="utf-8"))
    assert topology["status"] == "PASS"
    assert topology["nodes"]
    assert topology["datasets"]
    assert topology["runtime_authority"] is False
    assert topology["promotion_authority"] is False
