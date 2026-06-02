from __future__ import annotations

from pathlib import Path

from scripts.v17_7_1_mhm_common import read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_1_policy_causal_graph_has_required_nodes() -> None:
    graph = read_json(ROOT / "reports" / "v17_7_1_policy_causal_graph.json")
    required = {"features", "rules", "route decision", "route margin", "selected route", "base preservation", "harmful activation", "oracle gap", "slice/dataset", "perturbation stability", "score outcome"}
    assert required <= set(graph["nodes"])
    assert graph["durable_improvement_or_artifact"] == "dataset_slice_artifact_risk_not_ruled_out"
