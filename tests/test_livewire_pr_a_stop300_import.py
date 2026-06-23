from __future__ import annotations

import hashlib
import importlib.util
import json
import copy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load(rel: str):
    return json.loads((ROOT / rel).read_text(encoding="utf-8-sig"))


def canonical_sha(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def load_semantic_court():
    spec = importlib.util.spec_from_file_location("semantic", ROOT / "scripts/validate_livewire_semantic_invariants.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_stop300_cleanroom_receipt_preserves_official_block_and_counterfactual_split():
    recompute = load("evidence/stop300/stop300_cleanroom_recomputation_v2.json")
    assert recompute["derived_field_dependency_count"] == 0
    assert recompute["record_count_total"] == 1185
    assert recompute["measured_record_count"] == 1176
    assert recompute["natural_pair_count"] == 300
    assert recompute["timing_triplet_count"] == 180
    assert recompute["edge_execution_count"] == 36
    assert recompute["l0_correct"] == 261
    assert recompute["s1_correct"] == 261
    assert recompute["paired_correctness_damage"] == 0
    assert recompute["output_tokens_saved"] == 1500
    assert recompute["raw_prefix_mismatch_count"] == 0
    assert recompute["official_unlawful_reference_count"] == 3
    assert recompute["official_recomputed_status"] == "BLOCK_UNSAFE_STOP"
    assert recompute["repaired_counterfactual_status"] == "BLOCK_TOKEN_ECONOMICS"

    bundle = load("reports/livewire_pr_a_receipt_bundle.json")
    official = bundle["official_block_preservation_receipt"]
    counterfactual = bundle["repaired_court_counterfactual_receipt"]
    assert official["official_verdict_preserved"] is True
    assert official["official_verdict_overwritten"] is False
    assert official["official_primary_status"] == "BLOCK_UNSAFE_STOP"
    assert counterfactual["counterfactual_scope"] == "REPAIRED_COURT_ONLY_NOT_OFFICIAL_VERDICT"
    assert counterfactual["official_primary_status_remains"] == "BLOCK_UNSAFE_STOP"


def test_heavy_stop300_evidence_is_pointer_only_not_vendored():
    source_index = load("SOURCE_EVIDENCE_INDEX.json")
    sources = {source["source_id"]: source for source in source_index["sources"]}
    assert sources["src:stop300_assessment"]["packet_relative_path"] is None
    assert sources["src:stop300_assessment"]["repo_path"] is None
    assert sources["src:stop300_assessment"]["transport_identity_status"] == "REPACKAGED_NOT_BYTE_IDENTICAL"
    assert sources["src:stop300_pair_rows"]["packet_relative_path"] is None
    assert sources["src:stop300_pair_rows"]["repo_path"] is None
    assert not (ROOT / "evidence/stop300/KT_STOP300_V4_1_ASSESSMENT_ONLY_HF_RECOVERED.zip").exists()
    assert not (ROOT / "evidence/stop300/stop300_cleanroom_pair_rows_v2.jsonl").exists()


def test_graph_truth_claims_and_registry_reconcile_current_authority():
    graph = load("reports/livewire_pr_a_system_evidence_graph_payload.json")
    truth = load("reports/livewire_pr_a_current_program_truth_payload.json")
    decisions = load("reports/livewire_pr_a_claim_decisions.json")["decisions"]
    registry = load("registry/artifact_authority_registry.json")

    assert truth["generated_from_graph_sha256"] == canonical_sha(graph)
    assert truth["open_contradiction_count"] == 0

    nodes = {node["node_id"]: node for node in graph["nodes"]}
    assert nodes["fact:stop300_v41_official_block"]["status"] == "BLOCK_UNSAFE_STOP"
    assert nodes["fact:stop300_v41_counterfactual"]["status"] == "BLOCK_TOKEN_ECONOMICS_COUNTERFACTUAL_ONLY"
    assert nodes["authority:stop300_run_next_demoted"]["authority_state"] == "STALE"
    assert nodes["product:stop300_verify_demo"]["status"] == "NOT_PRODUCTIZED"

    decision = decisions[0]
    assert decision["decision"] == "ALLOW_INTERNAL"
    assert "runtime authority" in decision["forbidden_claim_classes"]
    assert "official result remains BLOCK_UNSAFE_STOP" in decision["limitations"]

    artifacts = {artifact["artifact_id"]: artifact for artifact in registry["artifacts"]}
    assert artifacts["stop300_v41_packet_decision"]["authority_state"] == "STALE"
    assert artifacts["stop300_v41_packet_decision"]["controls_execution"] is False
    assert artifacts["livewire_pr_a_system_evidence_graph_payload"]["authority_state"] == "LIVE_CURRENT_HEAD_VALIDATED"


def test_semantic_court_rejects_false_pass_fixtures():
    court = load_semantic_court()
    source_index = load("SOURCE_EVIDENCE_INDEX.json")
    graph = load("reports/livewire_pr_a_system_evidence_graph_payload.json")
    court.validate_source_index(source_index, ROOT)
    court.validate_graph(graph, source_index)
    court.validate_current_truth(load("reports/livewire_pr_a_current_program_truth_payload.json"), graph)
    court.validate_claim_decisions(load("reports/livewire_pr_a_claim_decisions.json")["decisions"], graph)

    bad_graph = copy.deepcopy(graph)
    bad_graph["contradictions"] = [
        {
            "contradiction_id": "bad:open",
            "subject": "open contradiction must fail",
            "conflicting_source_refs": ["src:stop300_cleanroom", "src:claim_ceiling_snapshot"],
            "status": "OPEN",
            "resolution_ref": None,
        }
    ]
    try:
        court.validate_graph(bad_graph, source_index)
    except court.SemanticError:
        pass
    else:
        raise AssertionError("semantic court accepted open graph contradiction")

    bad_truth = copy.deepcopy(load("reports/livewire_pr_a_current_program_truth_payload.json"))
    bad_truth["generated_from_graph_sha256"] = "0" * 64
    try:
        court.validate_current_truth(bad_truth, graph)
    except court.SemanticError:
        pass
    else:
        raise AssertionError("semantic court accepted mismatched graph digest")

    bad_decisions = copy.deepcopy(load("reports/livewire_pr_a_claim_decisions.json"))["decisions"]
    bad_decisions[0]["decision"] = "BLOCK"
    try:
        court.validate_claim_decisions(bad_decisions, graph)
    except court.SemanticError:
        pass
    else:
        raise AssertionError("semantic court accepted a BLOCK decision with allowed claims")
