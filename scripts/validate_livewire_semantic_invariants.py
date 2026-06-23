#!/usr/bin/env python3
"""Semantic invariant court for KT Core Livewire V2.2.

JSON Schema prevents malformed shapes. This court prevents internally coherent lies.
It is intentionally dependency-light and can run in CI, a fresh clone, or a detached
reviewer environment.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any, Iterable

EPS = 1e-12


class SemanticError(ValueError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def load_json(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def require(condition: bool, code: str) -> None:
    if not condition:
        raise SemanticError(code)


def unique(values: Iterable[str], code: str) -> None:
    items = list(values)
    require(len(items) == len(set(items)), code)


def ratio_equal(numerator: int, denominator: int, declared: float, code: str) -> None:
    require(denominator > 0, f"{code}:zero_denominator")
    require(math.isclose(numerator / denominator, float(declared), rel_tol=0.0, abs_tol=EPS), code)


def validate_graph(graph: dict[str, Any], source_index: dict[str, Any] | None = None) -> None:
    nodes = graph["nodes"]
    edges = graph["edges"]
    unique((n["node_id"] for n in nodes), "graph:duplicate_node_id")
    unique((e["edge_id"] for e in edges), "graph:duplicate_edge_id")
    node_map = {n["node_id"]: n for n in nodes}
    for edge in edges:
        require(edge["from_node"] in node_map, f"graph:missing_from_node:{edge['edge_id']}")
        require(edge["to_node"] in node_map, f"graph:missing_to_node:{edge['edge_id']}")
        require(edge["observed_head"] == graph["generated_from_head"], f"graph:mixed_head:{edge['edge_id']}")

    plane_expectation = {
        "authority_decision": "AUTHORITY",
        "claim_decision": "CLAIM",
        "claim": "CLAIM",
        "deployment": "PRODUCT",
        "product_exposure": "PRODUCT",
        "fact": "FACT",
        "result": "FACT",
    }
    for node in nodes:
        expected = plane_expectation.get(node["node_type"])
        if expected:
            require(node["truth_plane"] == expected, f"graph:truth_plane_mismatch:{node['node_id']}")
        require(node["last_verified_head"] == graph["generated_from_head"], f"graph:node_mixed_head:{node['node_id']}")
        if node["authority_state"] in {"CURRENT_HEAD", "EXTERNAL", "COMMERCIAL"}:
            require(node["payload_sha256"] is not None, f"graph:authoritative_node_without_payload_hash:{node['node_id']}")
        if node["claim_authority"] == "COMMERCIAL":
            require(node["authority_state"] == "COMMERCIAL", f"graph:commercial_claim_without_commercial_authority:{node['node_id']}")

    # Supersession must be a DAG.
    supersedes: dict[str, list[str]] = defaultdict(list)
    indegree: Counter[str] = Counter()
    involved: set[str] = set()
    for edge in edges:
        if edge["edge_type"] == "SUPERSEDES":
            supersedes[edge["from_node"]].append(edge["to_node"])
            indegree[edge["to_node"]] += 1
            involved.update((edge["from_node"], edge["to_node"]))
    queue = deque(sorted(n for n in involved if indegree[n] == 0))
    visited = 0
    while queue:
        current = queue.popleft()
        visited += 1
        for child in supersedes[current]:
            indegree[child] -= 1
            if indegree[child] == 0:
                queue.append(child)
    require(visited == len(involved), "graph:supersedes_cycle")

    # One controlling claim-decision node, many evidence parents.
    incoming: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        incoming[edge["to_node"]].append(edge)
    claims = [n for n in nodes if n["node_type"] == "claim"]
    for claim in claims:
        decisions = [e for e in incoming[claim["node_id"]] if e["edge_type"] == "DECIDES_CLAIM"]
        require(len(decisions) == 1, f"graph:claim_decision_cardinality:{claim['node_id']}")
        decision_node = node_map[decisions[0]["from_node"]]
        require(decision_node["node_type"] == "claim_decision", f"graph:invalid_claim_decider:{claim['node_id']}")
        parents = [e for e in incoming[decision_node["node_id"]] if e["edge_type"] == "SUPPORTS"]
        require(len({e["from_node"] for e in parents}) >= 2, f"graph:claim_decision_insufficient_evidence:{claim['node_id']}")
        parent_planes = {node_map[e["from_node"]]["truth_plane"] for e in parents}
        require("FACT" in parent_planes and "AUTHORITY" in parent_planes,
                f"graph:claim_decision_missing_fact_or_authority_parent:{claim['node_id']}")

    for edge in edges:
        source = node_map[edge["from_node"]]
        target = node_map[edge["to_node"]]
        if edge["edge_type"] == "DECIDES_CLAIM":
            require(source["node_type"] == "claim_decision" and target["node_type"] == "claim",
                    f"graph:illegal_decides_claim_edge:{edge['edge_id']}")
        if edge["edge_type"] == "EXPOSES_PRODUCT":
            require(target["truth_plane"] == "PRODUCT", f"graph:illegal_product_edge:{edge['edge_id']}")
        if edge["edge_type"] == "AUTHORIZES":
            require(source["truth_plane"] == "AUTHORITY", f"graph:non_authority_authorizes:{edge['edge_id']}")

    open_contradictions = [c for c in graph["contradictions"] if c["status"] == "OPEN"]
    require(not open_contradictions, "graph:open_contradiction")
    for contradiction in graph["contradictions"]:
        if contradiction["status"] != "OPEN":
            require(contradiction["resolution_ref"] is not None, f"graph:resolved_contradiction_without_resolution:{contradiction['contradiction_id']}")

    if source_index is not None:
        source_ids = {s["source_id"] for s in source_index["sources"]}
        for node in nodes:
            require(set(node["source_refs"]).issubset(source_ids), f"graph:unresolved_node_source_ref:{node['node_id']}")
        for edge in edges:
            require(set(edge["source_refs"]).issubset(source_ids), f"graph:unresolved_edge_source_ref:{edge['edge_id']}")


def validate_current_truth(projection: dict[str, Any], graph: dict[str, Any]) -> None:
    graph_hash = sha256_json(graph)
    require(projection["generated_from_graph_sha256"] == graph_hash, "current_truth:graph_hash_mismatch")
    require(projection["generated_from_head"] == graph["generated_from_head"], "current_truth:head_mismatch")
    require(projection["source_set_sha256"] == graph["source_set_sha256"], "current_truth:source_set_mismatch")
    require(projection["open_contradiction_count"] == 0, "current_truth:open_contradictions")
    require(not any(c["status"] == "OPEN" for c in graph["contradictions"]), "current_truth:graph_open_contradictions")
    nodes = {n["node_id"]: n for n in graph["nodes"]}
    decision_refs: Counter[str] = Counter()
    for plane in ("fact_truth", "authority_truth", "claim_truth", "product_truth"):
        unique((r["result_id"] for r in projection[plane]), f"current_truth:duplicate_result:{plane}")
        for row in projection[plane]:
            require(row["claim_decision_ref"] in nodes, f"current_truth:missing_claim_decision:{row['result_id']}")
            require(nodes[row["claim_decision_ref"]]["node_type"] == "claim_decision",
                    f"current_truth:wrong_claim_decision_type:{row['result_id']}")
            require(set(row["fact_refs"]).issubset(nodes), f"current_truth:missing_fact_ref:{row['result_id']}")
            for fact_ref in row["fact_refs"]:
                require(nodes[fact_ref]["truth_plane"] == "FACT", f"current_truth:non_fact_reference:{row['result_id']}:{fact_ref}")
            decision_refs[row["result_id"]] += 1
    # Each projected result has a single decision reference within its plane object.
    require(all(count == 1 for count in decision_refs.values()), "current_truth:duplicate_cross_plane_result_id")


def validate_claim_decisions(decisions: list[dict[str, Any]], graph: dict[str, Any]) -> None:
    unique((d["claim_id"] for d in decisions), "claim_decision:duplicate_claim_id")
    unique((d["decision_node_id"] for d in decisions), "claim_decision:duplicate_decision_node")
    nodes = {n["node_id"]: n for n in graph["nodes"]}
    for decision in decisions:
        require(decision["decision_node_id"] in nodes, f"claim_decision:node_missing:{decision['claim_id']}")
        require(nodes[decision["decision_node_id"]]["node_type"] == "claim_decision", f"claim_decision:wrong_node_type:{decision['claim_id']}")
        require(decision["generated_from_head"] == graph["generated_from_head"], f"claim_decision:head_mismatch:{decision['claim_id']}")
        payload = {k: v for k, v in decision.items() if k != "decision_sha256"}
        require(sha256_json(payload) == decision["decision_sha256"], f"claim_decision:digest_mismatch:{decision['claim_id']}")
        if decision["decision"] == "BLOCK":
            require(not decision["allowed_claim_classes"], f"claim_decision:block_has_allowed_claims:{decision['claim_id']}")
        if decision["decision"] in {"ALLOW_INTERNAL", "ALLOW_BOUNDED_PILOT"}:
            require(bool(decision["allowed_claim_classes"]), f"claim_decision:allow_without_class:{decision['claim_id']}")


def validate_maturity(maturity: dict[str, Any]) -> None:
    impl = maturity["implementation_status"]
    validation = maturity["validation_status"]
    activation = maturity["activation_status"]
    evidence = maturity["evidence_status"]
    authority = maturity["authority_status"]
    externality = maturity["externality_status"]
    product = maturity["product_status"]
    if impl == "CONCEPT_ONLY":
        require(validation == "UNTESTED" and activation == "UNWIRED" and evidence in {"NONE", "SCAFFOLD_ONLY"},
                "maturity:concept_claims_execution")
    if validation not in {"UNTESTED", "BLOCKED"}:
        require(impl in {"CODE_EXISTS", "CONFIGURED"}, "maturity:validated_without_implementation")
        require(bool(maturity["evidence_refs"]), "maturity:validated_without_evidence")
    if activation == "RUNTIME_LIVE":
        require(impl == "CONFIGURED", "maturity:runtime_live_not_configured")
        require(validation in {"CI_VALIDATED", "FURNACE_VALIDATED", "DETACHED_RECOMPUTED"}, "maturity:runtime_live_without_validation")
        require(evidence in {"RAW_EVIDENCE_BOUND", "NO_REGRESSION_CONFIRMED", "EXTERNALLY_REPLAYED"}, "maturity:runtime_live_without_raw_evidence")
        require(authority not in {"NONE", "LAB_ONLY", "PREP_ONLY"}, "maturity:runtime_live_without_authority")
    if evidence == "EXTERNALLY_REPLAYED":
        require(externality in {"UNAFFILIATED_REPLAY", "CUSTOMER_VALIDATED"}, "maturity:external_evidence_without_external_replay")
    if product in {"PRODUCTIZED", "COMMERCIALIZED"}:
        require(activation == "RUNTIME_LIVE", "maturity:product_without_runtime")
        require(externality in {"UNAFFILIATED_REPLAY", "CUSTOMER_VALIDATED"}, "maturity:product_without_externality")
    if product == "COMMERCIALIZED":
        require(authority == "COMMERCIAL" and externality == "CUSTOMER_VALIDATED", "maturity:commercialized_without_commercial_authority")
    if maturity["blockers"]:
        require(activation != "RUNTIME_LIVE" or authority not in {"EXTERNAL", "COMMERCIAL"}, "maturity:blockers_hidden_by_high_authority")


def validate_gate_coverage(gate: dict[str, Any]) -> None:
    require(gate["mandatory_gate_count"] >= 1, "gate:empty_mandatory_set")
    require(gate["static_path_count"] >= 1, "gate:empty_static_denominator")
    require(gate["dynamic_opportunity_count"] >= 1, "gate:empty_dynamic_denominator")
    require(gate["static_reachable_count"] == gate["static_path_count"], "gate:static_count_mismatch")
    require(gate["dynamic_invoked_count"] == gate["dynamic_opportunity_count"], "gate:dynamic_count_mismatch")
    require(gate["mutation_generated_count"] >= gate["mandatory_gate_count"], "gate:insufficient_mutants")
    require(gate["mutation_killed_count"] == gate["mutation_generated_count"], "gate:mutation_not_all_killed")
    require(gate["mutation_survived_count"] == 0, "gate:surviving_mutants")
    ratio_equal(gate["static_reachable_count"], gate["static_path_count"], gate["static_reachability_coverage"], "gate:static_ratio_lie")
    ratio_equal(gate["dynamic_invoked_count"], gate["dynamic_opportunity_count"], gate["dynamic_invocation_coverage"], "gate:dynamic_ratio_lie")
    ratio_equal(gate["mutation_killed_count"], gate["mutation_generated_count"], gate["mutation_kill_rate"], "gate:mutation_ratio_lie")
    for field in ("unknown_execution_path_count", "unclassified_applicability_count", "uninstrumented_path_count", "unauthorized_bypass_count"):
        require(gate[field] == 0, f"gate:{field}_nonzero")


def validate_mutation_ledger(ledger: dict[str, Any]) -> None:
    attacks = ledger["attacks"]
    unique((a["attack_id"] for a in attacks), "mutation:duplicate_attack_id")
    require(ledger["generated_count"] == len(attacks), "mutation:generated_count_lie")
    killed = sum(a["status"] == "PASS_FAIL_CLOSED" for a in attacks)
    survived = sum(a["status"] == "FAIL_OPEN" for a in attacks)
    blocked = sum(a["status"] == "BLOCKED_NOT_EXECUTED" for a in attacks)
    require(blocked == 0, "mutation:unexecuted_attack")
    require(ledger["killed_count"] == killed, "mutation:killed_count_lie")
    require(ledger["survived_count"] == survived, "mutation:survived_count_lie")
    require(killed + survived == ledger["generated_count"], "mutation:count_partition_error")
    ratio_equal(killed, ledger["generated_count"], ledger["kill_rate"], "mutation:kill_rate_lie")
    require(ledger["kill_rate"] == 1.0, "mutation:incomplete_kill_rate")
    for attack in attacks:
        if attack["status"] == "PASS_FAIL_CLOSED":
            require(attack["expected_blocker"] == attack["observed_blocker"], f"mutation:wrong_blocker:{attack['attack_id']}")


def event_digest(event: dict[str, Any]) -> str:
    body = {k: v for k, v in event.items() if k != "event_sha256"}
    return sha256_json(body)


def validate_proof_invocation(proof: dict[str, Any]) -> None:
    require(proof["ended_monotonic_ns"] >= proof["started_monotonic_ns"], "proof:negative_duration")
    events = proof["events"]
    require([e["sequence"] for e in events] == list(range(len(events))), "proof:event_sequence_gap")
    previous = None
    last_time = proof["started_monotonic_ns"]
    for event in events:
        require(event["previous_event_sha256"] == previous, f"proof:broken_previous_hash:{event['sequence']}")
        require(event["monotonic_ns"] >= last_time, f"proof:nonmonotonic_event:{event['sequence']}")
        require(event["event_sha256"] == event_digest(event), f"proof:event_digest_mismatch:{event['sequence']}")
        previous = event["event_sha256"]
        last_time = event["monotonic_ns"]
    require(previous == proof["event_chain_root_sha256"], "proof:event_chain_root_mismatch")
    require(last_time <= proof["ended_monotonic_ns"], "proof:event_after_end")
    event_types = {e["event_type"] for e in events}
    required_events = {"INPUT_ACCEPTED", "COMPONENT_INVOKED", "GATE_EVALUATED", "OUTPUT_PRESERVED", "OUTPUT_DELIVERED", "EFFECT_MEASURED", "EXECUTION_CLOSED"}
    require(required_events.issubset(event_types), "proof:missing_required_event")
    gates = proof["gates"]
    unique((g["gate_id"] for g in gates), "proof:duplicate_gate")
    for gate in gates:
        if gate["mandatory"] and gate["applicable"]:
            require(gate["invoked"], f"proof:mandatory_gate_not_invoked:{gate['gate_id']}")
            require(gate["decision"] != "NOT_APPLICABLE", f"proof:applicable_gate_marked_na:{gate['gate_id']}")
        if not gate["applicable"]:
            require(gate["decision"] == "NOT_APPLICABLE", f"proof:inapplicable_gate_has_decision:{gate['gate_id']}")
    outputs = proof["outputs"]
    if outputs["verifier_status"] == "PASS" or outputs["correctness"] is not None:
        require(all(outputs[k] is not None for k in ("raw_sha256", "preserved_sha256", "delivered_sha256", "scored_sha256")),
                "proof:scored_output_missing_hash")
    rollback = proof["rollback"]
    if rollback["tested"]:
        require(rollback["available"] and rollback["receipt_sha256"] is not None and "ROLLBACK_TESTED" in event_types,
                "proof:rollback_claim_not_proven")
    if not rollback["available"]:
        require(not rollback["tested"] and rollback["receipt_sha256"] is None, "proof:unavailable_rollback_claimed")
    # Internal attestation binds the full proof except its own digest.
    if proof["attestation_mode"] == "INTERNAL_HASH_CHAIN":
        body = {k: v for k, v in proof.items() if k != "detached_attestation_sha256"}
        require(proof["detached_attestation_sha256"] == sha256_json(body), "proof:attestation_digest_mismatch")


def validate_lobe_selection(selection: dict[str, Any]) -> None:
    evidence = selection["selection_evidence"]
    total = sum(float(row["weight"]) for row in evidence)
    require(math.isclose(total, 1.0, rel_tol=0.0, abs_tol=EPS), "lobe:weight_sum_lie")
    by_family: dict[str, float] = defaultdict(float)
    for row in evidence:
        by_family[row["source_family"]] += float(row["weight"])
    require(len(by_family) >= 3, "lobe:insufficient_independent_families")
    maximum = max(by_family.values())
    hhi = sum(value * value for value in by_family.values())
    effective = 1.0 / hhi
    require(maximum <= 0.4 + EPS, "lobe:family_concentration_too_high")
    require(hhi <= 0.4 + EPS, "lobe:hhi_too_high")
    require(effective >= 2.5 - EPS, "lobe:effective_family_count_too_low")
    require(selection["independent_source_family_count"] == len(by_family), "lobe:family_count_lie")
    require(math.isclose(selection["max_aggregate_family_share"], maximum, abs_tol=EPS), "lobe:max_share_lie")
    require(math.isclose(selection["herfindahl_concentration"], hhi, abs_tol=EPS), "lobe:hhi_lie")
    require(math.isclose(selection["effective_independent_family_count"], effective, abs_tol=EPS), "lobe:effective_count_lie")
    require(selection["family_weight_sum"] == 1.0, "lobe:declared_weight_sum_lie")
    require(selection["selection_confirmation_disjoint"] is True, "lobe:split_not_declared_disjoint")


def validate_split_report(report: dict[str, Any]) -> None:
    overlap_fields = [
        "row_id_overlap_count", "question_hash_overlap_count", "normalized_text_exact_overlap_count",
        "near_duplicate_overlap_count", "source_document_overlap_count", "template_family_overlap_count",
        "generated_variant_overlap_count", "teacher_trace_overlap_count", "gold_provenance_overlap_count",
    ]
    for field in overlap_fields:
        require(report[field] == 0, f"split:{field}_nonzero")
    require(report["status"] == "PASS_DISJOINT", "split:false_pass_status")


def validate_reviewer(reviewer: dict[str, Any], ledger: dict[str, Any]) -> None:
    require(reviewer["imports_kt_runtime_code"] is False, "reviewer:imports_runtime")
    require(reviewer["offline_integrity_mode"]["network_enabled"] is False, "reviewer:offline_network_enabled")
    require(reviewer["offline_integrity_mode"]["mutation_ledger_ref"], "reviewer:missing_mutation_ledger_ref")
    validate_mutation_ledger(ledger)
    required_attacks = {
        "TAMPERED_ZIP", "WRONG_HASH", "HEAD_BINDING_MISMATCH", "MISSING_RECEIPT",
        "ALTERED_SCORECARD", "DUPLICATE_ROW", "UNSUPPORTED_CLAIM", "PATH_TRAVERSAL",
        "SYMLINK_OR_SPECIAL_FILE", "UNICODE_COLLISION", "SCHEMA_DOWNGRADE",
        "SOURCE_SUBSTITUTION", "COUNTERFACTUAL_LAUNDERING",
    }
    actual = {a["attack_class"] for a in ledger["attacks"]}
    require(required_attacks.issubset(actual), "reviewer:missing_required_attack_class")
    online = reviewer["online_freshness_mode"]
    if online["status"] == "NOT_RUN_NETWORK_DISABLED":
        require(not online["network_enabled"] and online["observed_remote_head"] is None and online["release_or_revocation_status"] == "UNKNOWN_NOT_CHECKED",
                "reviewer:offline_mode_claims_freshness")
    if online["status"] == "PASS_CURRENT_HEAD_CONFIRMED":
        require(online["network_enabled"] and online["observed_remote_head"] is not None and online["release_or_revocation_status"] == "CURRENT" and online["evidence_ref"] is not None,
                "reviewer:online_freshness_without_evidence")


def validate_source_index(index: dict[str, Any], packet_root: Path) -> None:
    unique((s["source_id"] for s in index["sources"]), "source_index:duplicate_source_id")
    for source in index["sources"]:
        path = source["packet_relative_path"]
        if path is not None:
            require(not Path(path).is_absolute(), f"source_index:absolute_path:{source['source_id']}")
            resolved = (packet_root / path).resolve()
            require(str(resolved).startswith(str(packet_root.resolve())), f"source_index:path_escape:{source['source_id']}")
            require(resolved.is_file(), f"source_index:missing_packet_file:{source['source_id']}")
            data = resolved.read_bytes()
            require(len(data) == source["bytes"], f"source_index:size_mismatch:{source['source_id']}")
            require(hashlib.sha256(data).hexdigest() == source["sha256"], f"source_index:hash_mismatch:{source['source_id']}")
        if source["authority_class"] == "RECOVERED_REPACKAGED_EVIDENCE":
            require(source["transport_identity_status"] == "REPACKAGED_NOT_BYTE_IDENTICAL", f"source_index:repackaged_misclassified:{source['source_id']}")
        if source["authority_class"] == "NONCONTROLLING_CONTEXT":
            require(source["controlling"] is False, f"source_index:context_marked_controlling:{source['source_id']}")


def validate_path(kind: str, path: str, graph: dict[str, Any] | None, source_index: dict[str, Any] | None, mutation: dict[str, Any] | None) -> None:
    obj = load_json(path)
    if kind == "graph": validate_graph(obj, source_index)
    elif kind == "current_truth":
        require(graph is not None, "cli:current_truth_requires_graph")
        validate_current_truth(obj, graph)
    elif kind == "claim_decisions":
        require(graph is not None, "cli:claim_decisions_requires_graph")
        validate_claim_decisions(obj if isinstance(obj, list) else obj["decisions"], graph)
    elif kind == "maturity": validate_maturity(obj)
    elif kind == "gate": validate_gate_coverage(obj)
    elif kind == "mutation": validate_mutation_ledger(obj)
    elif kind == "proof": validate_proof_invocation(obj)
    elif kind == "lobe": validate_lobe_selection(obj)
    elif kind == "split": validate_split_report(obj)
    elif kind == "reviewer":
        require(mutation is not None, "cli:reviewer_requires_mutation")
        validate_reviewer(obj, mutation)
    else: raise SemanticError(f"cli:unknown_kind:{kind}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--source-index")
    parser.add_argument("--graph")
    parser.add_argument("--current-truth")
    parser.add_argument("--claim-decisions")
    parser.add_argument("--maturity")
    parser.add_argument("--gate")
    parser.add_argument("--mutation")
    parser.add_argument("--proof")
    parser.add_argument("--lobe")
    parser.add_argument("--split")
    parser.add_argument("--reviewer")
    args = parser.parse_args()
    root = Path(args.packet_root).resolve()
    source_index = load_json(args.source_index) if args.source_index else None
    if source_index is not None:
        validate_source_index(source_index, root)
    graph = load_json(args.graph) if args.graph else None
    if graph is not None:
        validate_graph(graph, source_index)
    mutation = load_json(args.mutation) if args.mutation else None
    if mutation is not None:
        validate_mutation_ledger(mutation)
    for kind, path in (
        ("current_truth", args.current_truth), ("claim_decisions", args.claim_decisions),
        ("maturity", args.maturity), ("gate", args.gate), ("proof", args.proof),
        ("lobe", args.lobe), ("split", args.split), ("reviewer", args.reviewer),
    ):
        if path:
            validate_path(kind, path, graph, source_index, mutation)
    print("livewire_semantic_invariants_pass")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SemanticError, KeyError, TypeError, ValueError) as exc:
        print(f"livewire_semantic_invariants_fail:{exc}", file=sys.stderr)
        raise SystemExit(1)
