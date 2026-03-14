from __future__ import annotations

import sys
from pathlib import Path

import jsonschema

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.structural_graph_catalog_compile import build_graph_and_catalog_reports  # noqa: E402
from tools.operator.titanium_common import load_json, repo_root, semantically_equal_json  # noqa: E402


def test_step6_reports_validate_and_cover_required_planes() -> None:
    root = repo_root()
    reports = build_graph_and_catalog_reports(root=root, generated_utc="2026-03-14T00:00:00Z")
    schema = load_json(root / "KT_PROD_CLEANROOM/governance/foundation_pack/kt_fact_graph.schema.json")

    for key in ("fact_graph", "temporal_graph", "data_lineage", "runtime_graph"):
        jsonschema.validate(instance=reports[key], schema=schema)

    assert reports["adapter_registry"]["adapters"]
    assert reports["model_registry"]["models"]
    assert reports["sector_harness_registry"]["sectors"]
    assert reports["symbol_index"]["symbols"]
    assert reports["contract_index"]["contracts"]
    assert reports["truth_surface_map"]["surfaces"]

    temporal_edge_types = {edge["edge_type"] for edge in reports["temporal_graph"]["edges"]}
    assert {"supersedes", "superseded_by"} & temporal_edge_types
    assert "has_temporal_status" in temporal_edge_types

    lineage_node_types = {node["node_type"] for node in reports["data_lineage"]["nodes"]}
    assert {"adapter", "model", "sector", "data_asset"}.issubset(lineage_node_types)


def test_step6_reports_are_semantically_deterministic() -> None:
    root = repo_root()
    first = build_graph_and_catalog_reports(root=root, generated_utc="2026-03-14T00:00:00Z")
    second = build_graph_and_catalog_reports(root=root, generated_utc="2026-03-14T00:00:00Z")

    for key in first:
        assert semantically_equal_json(first[key], second[key]), key
