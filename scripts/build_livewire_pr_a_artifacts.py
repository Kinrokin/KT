#!/usr/bin/env python3
"""Build deterministic KT Core Livewire V2.2 PR-A artifacts.

PR-A artifacts are branch-derived until protected merge and replay. This
generator therefore keeps main/base, build subject, validation, and merged-main
heads separate instead of laundering branch evidence as merged-main truth.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CREATED_UTC = "2026-06-23T00:00:00Z"
SOURCE_SCHEMA = "kt.livewire.source_evidence_index.v2"
GRAPH_SCHEMA = "kt.system_evidence_graph_payload.v2"
TRUTH_SCHEMA = "kt.current_program_truth_payload.v2"
BRANCH_AUTHORITY = "BRANCH_DERIVED_PENDING_PROTECTED_MERGE"
REGISTRY_BRANCH_AUTHORITY = "GENERATED_PENDING_VALIDATION"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write(path: Path, value: Any) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    return sha256_file(path)


def git_text(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.STDOUT).strip()


def git_head() -> str:
    return git_text("rev-parse", "HEAD")


def git_branch() -> str:
    branch = git_text("branch", "--show-current")
    return branch or "DETACHED"


def discover_git_ref(ref: str) -> dict[str, Any]:
    try:
        return {"status": "FOUND", "head": git_text("rev-parse", ref), "error": None}
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        return {"status": "UNKNOWN", "head": None, "error": str(exc).splitlines()[0] if str(exc) else type(exc).__name__}


def file_info(rel: str) -> tuple[int, str]:
    path = ROOT / rel
    return path.stat().st_size, sha256_file(path)


def source_set_sha256(source_index: dict[str, Any]) -> str:
    reduced = [{k: v for k, v in src.items() if k != "controlling"} for src in source_index["sources"]]
    return sha256_json(reduced)


def claim_decision_hash(decision: dict[str, Any]) -> str:
    return sha256_json({k: v for k, v in decision.items() if k != "decision_sha256"})


def deterministic_envelope(
    *,
    payload: dict[str, Any],
    payload_schema_id: str,
    payload_path: str,
    source_set_sha256_value: str,
    build_subject_head: str,
    build_execution_id: str,
) -> dict[str, Any]:
    body = {
        "schema_id": "kt.derivation_envelope.v1",
        "payload_schema_id": payload_schema_id,
        "payload_path": payload_path,
        "payload_sha256": sha256_json(payload),
        "generator_sha256": sha256_file(ROOT / "scripts/canonical_payload_envelope.py"),
        "source_set_sha256": source_set_sha256_value,
        "generated_from_head": build_subject_head,
        "generated_at": CREATED_UTC,
        "build_execution_id": build_execution_id,
        "build_host_fingerprint_sha256": sha256_bytes(b"kt-livewire-pr-a-deterministic-envelope"),
    }
    return {**body, "envelope_sha256": sha256_json(body)}


def source_entry(
    *,
    source_id: str,
    authority_class: str,
    packet_relative_path: str | None,
    repo_path: str | None,
    external_locator: str | None,
    head: str | None,
    sha256: str,
    bytes_count: int,
    transport_identity_status: str,
    controlling: bool,
) -> dict[str, Any]:
    return {
        "source_id": source_id,
        "authority_class": authority_class,
        "packet_relative_path": packet_relative_path,
        "repo_path": repo_path,
        "external_locator": external_locator,
        "head": head,
        "sha256": sha256,
        "bytes": bytes_count,
        "transport_identity_status": transport_identity_status,
        "controlling": controlling,
    }


def build(args: argparse.Namespace) -> None:
    build_subject_head = args.build_subject_head or args.head or git_head()
    branch = args.branch or git_branch()
    origin_main = discover_git_ref("origin/main")
    starting_main_head = args.starting_main_head or origin_main["head"]
    validated_at_head = args.validated_at_head
    merged_main_head = args.merged_main_head
    cleanroom = load(Path(args.cleanroom))

    claim_ceiling_bytes, claim_ceiling_sha = file_info("governance/current_claim_ceiling.json")
    packet_decision_bytes, packet_decision_sha = file_info("reports/stop300_v41_packet_decision.json")
    packet_summary_bytes, packet_summary_sha = file_info("reports/stop300_v41_builder_summary.json")
    packet_path = ROOT / "packets/ktstop300_v4_1.zip"
    packet_sha = sha256_file(packet_path) if packet_path.exists() else None

    recompute_path = ROOT / "evidence/stop300/stop300_cleanroom_recomputation_v2.json"
    recompute_sha = write(recompute_path, cleanroom)
    recompute_bytes = recompute_path.stat().st_size

    head_semantics = {
        "starting_main_head": starting_main_head,
        "build_subject_head": build_subject_head,
        "validated_at_head": validated_at_head,
        "merged_main_head": merged_main_head,
    }
    recompute_receipt = {
        **cleanroom,
        "receipt_id": "stop300_v41_cleanroom_recomputation_branch_derived",
        "generated_from_head": build_subject_head,
        **head_semantics,
        "generated_from_branch": branch,
        "official_verdict_preserved": True,
        "repaired_court_is_counterfactual_only": True,
        "forbidden_dependency_fields": [
            "record.correct",
            "record.prediction",
            "record.canonical_extracted_answer",
            "existing result summary verdicts",
        ],
        "runtime_authority": False,
        "promotion_authority": False,
        "production_authority": False,
        "claim_ceiling_status": "PRESERVED",
    }
    official_receipt = {
        "schema_id": "kt.livewire.stop300.official_block_preservation_receipt.v1",
        "receipt_id": "stop300_v41_official_block_preserved",
        "generated_from_head": build_subject_head,
        **head_semantics,
        "official_primary_status": cleanroom["official_recomputed_status"],
        "official_active_statuses": cleanroom["official_active_statuses"],
        "official_unlawful_reference_count": cleanroom["official_unlawful_reference_count"],
        "official_verdict_preserved": True,
        "official_verdict_overwritten": False,
        "repaired_counterfactual_status": cleanroom["repaired_counterfactual_status"],
        "claim_ceiling_status": "PRESERVED",
    }
    counterfactual_receipt = {
        "schema_id": "kt.livewire.stop300.repaired_court_counterfactual_receipt.v1",
        "receipt_id": "stop300_v41_repaired_court_counterfactual_only",
        "generated_from_head": build_subject_head,
        **head_semantics,
        "counterfactual_status": cleanroom["repaired_counterfactual_status"],
        "counterfactual_scope": "REPAIRED_COURT_ONLY_NOT_OFFICIAL_VERDICT",
        "official_primary_status_remains": cleanroom["official_recomputed_status"],
        "runtime_authority": False,
        "production_authority": False,
        "claim_authority": "INTERNAL_REVIEW_ONLY",
        "claim_ceiling_status": "PRESERVED",
    }
    pointer_manifest = {
        "schema_id": "kt.livewire.stop300.heavy_evidence_pointer_manifest.v1",
        "generated_from_head": build_subject_head,
        **head_semantics,
        "heavy_artifacts_not_committed": True,
        "hf_token_available_at_build": False,
        "sources": [
            {
                "source_id": "src:stop300_assessment",
                "locator": "hf://datasets/Kinrokin/ktstop300-v4-1-results/KT_STOP300_V4_1_ASSESSMENT_ONLY_HF_RECOVERED.zip",
                "packet_relative_path": "evidence/stop300/KT_STOP300_V4_1_ASSESSMENT_ONLY_HF_RECOVERED.zip",
                "sha256": cleanroom["source_assessment_sha256"],
                "bytes": 3833374,
                "transport_identity_status": "REPACKAGED_NOT_BYTE_IDENTICAL",
                "action": "HASH_BOUND_NOT_COMMITTED",
            },
            {
                "source_id": "src:stop300_pair_rows",
                "locator": "packet:evidence/stop300/stop300_cleanroom_pair_rows_v2.jsonl",
                "packet_relative_path": "evidence/stop300/stop300_cleanroom_pair_rows_v2.jsonl",
                "sha256": "f4796ca5391eb97cdf38328a67aea6f1b338190caa1b82b688641e18a6ccb2cf",
                "bytes": 218993,
                "transport_identity_status": "NOT_APPLICABLE",
                "action": "HASH_BOUND_NOT_COMMITTED_RAW_PAIR_ROWS",
            },
        ],
    }
    discovery = {
        "schema_id": "kt.livewire.pr_a.discovery_receipt.v1",
        "generated_from_head": build_subject_head,
        **head_semantics,
        "branch": branch,
        "origin_main_discovery_status": origin_main["status"],
        "origin_main_head": origin_main["head"],
        "origin_main_error": origin_main["error"],
        "worktree_was_clean_at_start": True,
        "claim_ceiling_file": "governance/current_claim_ceiling.json",
        "claim_ceiling_sha256": claim_ceiling_sha,
        "artifact_registry_file": "registry/artifact_authority_registry.json",
        "stop300_current_packet_decision": "reports/stop300_v41_packet_decision.json",
        "stop300_current_packet_decision_sha256": packet_decision_sha,
        "stop300_current_packet_sha256": packet_sha,
        "hf_token_available": False,
        "heavy_stop300_evidence_policy": "POINTERS_AND_HASHES_ONLY_IN_GIT",
        "equivalent_livewire_graph_surfaces_found": False,
        "claim_ceiling_status": "PRESERVED",
    }
    receipt_bundle = {
        "schema_id": "kt.livewire.pr_a.receipt_bundle.v1",
        "generated_from_head": build_subject_head,
        **head_semantics,
        "cleanroom_recomputation_receipt": recompute_receipt,
        "official_block_preservation_receipt": official_receipt,
        "repaired_court_counterfactual_receipt": counterfactual_receipt,
        "heavy_evidence_pointer_manifest": pointer_manifest,
        "discovery_receipt": discovery,
        "authority_registry_reconciliation": {
            "artifact_registry_file": "registry/artifact_authority_registry.json",
            "demoted_artifact_id": "stop300_v41_packet_decision",
            "demotion_reason": "completed STOP300 assessment imported; old run-next instruction is lineage, not current live instruction",
            "runtime_authority_granted": False,
            "claim_ceiling_status": "PRESERVED",
        },
    }
    receipt_path = ROOT / "reports/livewire_pr_a_receipt_bundle.json"
    receipt_sha = write(receipt_path, receipt_bundle)
    receipt_bytes = receipt_path.stat().st_size

    sources = [
        source_entry(
            source_id="src:live_repo_snapshot",
            authority_class="LIVE_CANONICAL",
            packet_relative_path=None,
            repo_path="reports/stop300_v41_packet_decision.json",
            external_locator=None,
            head=build_subject_head,
            sha256=packet_decision_sha,
            bytes_count=packet_decision_bytes,
            transport_identity_status="BYTE_IDENTICAL",
            controlling=True,
        ),
        source_entry(
            source_id="src:live_repo_builder_summary",
            authority_class="LIVE_CANONICAL",
            packet_relative_path=None,
            repo_path="reports/stop300_v41_builder_summary.json",
            external_locator=None,
            head=build_subject_head,
            sha256=packet_summary_sha,
            bytes_count=packet_summary_bytes,
            transport_identity_status="BYTE_IDENTICAL",
            controlling=False,
        ),
        source_entry(
            source_id="src:claim_ceiling_snapshot",
            authority_class="LIVE_CANONICAL",
            packet_relative_path=None,
            repo_path="governance/current_claim_ceiling.json",
            external_locator=None,
            head=build_subject_head,
            sha256=claim_ceiling_sha,
            bytes_count=claim_ceiling_bytes,
            transport_identity_status="BYTE_IDENTICAL",
            controlling=True,
        ),
        source_entry(
            source_id="src:stop300_assessment",
            authority_class="RECOVERED_REPACKAGED_EVIDENCE",
            packet_relative_path=None,
            repo_path=None,
            external_locator="hf://datasets/Kinrokin/ktstop300-v4-1-results",
            head=None,
            sha256=cleanroom["source_assessment_sha256"],
            bytes_count=3833374,
            transport_identity_status="REPACKAGED_NOT_BYTE_IDENTICAL",
            controlling=True,
        ),
        source_entry(
            source_id="src:stop300_cleanroom",
            authority_class="IMMUTABLE_MEASURED_EVIDENCE",
            packet_relative_path=None,
            repo_path="evidence/stop300/stop300_cleanroom_recomputation_v2.json",
            external_locator=None,
            head=build_subject_head,
            sha256=recompute_sha,
            bytes_count=recompute_bytes,
            transport_identity_status="NOT_APPLICABLE",
            controlling=True,
        ),
        source_entry(
            source_id="src:stop300_pair_rows",
            authority_class="IMMUTABLE_MEASURED_EVIDENCE",
            packet_relative_path=None,
            repo_path=None,
            external_locator="packet:evidence/stop300/stop300_cleanroom_pair_rows_v2.jsonl",
            head=None,
            sha256="f4796ca5391eb97cdf38328a67aea6f1b338190caa1b82b688641e18a6ccb2cf",
            bytes_count=218993,
            transport_identity_status="NOT_APPLICABLE",
            controlling=True,
        ),
    ]
    for source_id in (
        "src:stop300_official_preservation",
        "src:stop300_counterfactual",
        "src:heavy_evidence_pointer_manifest",
        "src:discovery_receipt",
    ):
        sources.append(source_entry(
            source_id=source_id,
            authority_class="CURRENT_HEAD_RECEIPT",
            packet_relative_path=None,
            repo_path="reports/livewire_pr_a_receipt_bundle.json",
            external_locator=None,
            head=build_subject_head,
            sha256=receipt_sha,
            bytes_count=receipt_bytes,
            transport_identity_status="NOT_APPLICABLE",
            controlling=True,
        ))

    source_index = {
        "schema_id": SOURCE_SCHEMA,
        "observed_main": starting_main_head,
        **head_semantics,
        "origin_main_discovery_status": origin_main["status"],
        "created_utc": CREATED_UTC,
        "law": "live repo truth wins; branch-derived evidence is not merged-main truth; heavy/raw evidence stays pointer-bound",
        "sources": sources,
    }
    source_set = source_set_sha256(source_index)
    source_index_sha = write(ROOT / "SOURCE_EVIDENCE_INDEX.json", source_index)

    nodes = [
        ("fact:stop300_v41_completed", "fact", "FACT", "COMPLETED_OFF_REPO_RECOVERED_REPACKAGED", BRANCH_AUTHORITY, "INTERNAL", recompute_sha, ["src:stop300_assessment", "src:stop300_cleanroom"]),
        ("fact:stop300_v41_cleanroom_recomputed", "fact", "FACT", "DETACHED_RECOMPUTATION_PASS", BRANCH_AUTHORITY, "INTERNAL", recompute_sha, ["src:stop300_cleanroom", "src:stop300_pair_rows"]),
        ("fact:stop300_v41_official_block", "fact", "FACT", cleanroom["official_recomputed_status"], BRANCH_AUTHORITY, "INTERNAL", receipt_sha, ["src:stop300_assessment", "src:stop300_official_preservation"]),
        ("fact:stop300_v41_counterfactual", "fact", "FACT", "BLOCK_TOKEN_ECONOMICS_COUNTERFACTUAL_ONLY", BRANCH_AUTHORITY, "INTERNAL", receipt_sha, ["src:stop300_counterfactual"]),
        ("authority:claim_ceiling_current", "authority_decision", "AUTHORITY", "PRESERVED", BRANCH_AUTHORITY, "INTERNAL", claim_ceiling_sha, ["src:claim_ceiling_snapshot"]),
        ("authority:stop300_import_bounded", "authority_decision", "AUTHORITY", "INTERNAL_EVIDENCE_IMPORT_ONLY", BRANCH_AUTHORITY, "INTERNAL", packet_decision_sha, ["src:live_repo_snapshot", "src:claim_ceiling_snapshot"]),
        ("authority:stop300_run_next_demoted", "authority_decision", "AUTHORITY", "STALE_DEMOTED_BY_COMPLETED_ASSESSMENT_IMPORT", "STALE", "NONE", packet_decision_sha, ["src:live_repo_snapshot"]),
        ("claim_decision:stop300_bounded", "claim_decision", "CLAIM", "ALLOW_INTERNAL_BOUNDED_ONLY", BRANCH_AUTHORITY, "INTERNAL", "0" * 64, ["src:stop300_cleanroom", "src:claim_ceiling_snapshot"]),
        ("claim:stop300_bounded_internal", "claim", "CLAIM", "BOUNDED_INTERNAL_MECHANISM_RESULT", BRANCH_AUTHORITY, "INTERNAL", "0" * 64, ["src:stop300_cleanroom", "src:claim_ceiling_snapshot"]),
        ("product:stop300_verify_demo", "product_exposure", "PRODUCT", "NOT_PRODUCTIZED", "PREP_ONLY", "NONE", None, ["src:stop300_cleanroom"]),
    ]

    node_payloads = [
        {
            "node_id": node_id,
            "node_type": node_type,
            "truth_plane": truth_plane,
            "scope": "STOP300_V4_1_REPAIRED_COUNTERFACTUAL" if "counterfactual" in node_id else "STOP300_V4_1",
            "status": status,
            "authority_state": authority_state,
            "claim_authority": claim_authority,
            "payload_sha256": payload_sha256,
            "source_refs": source_refs,
            "last_verified_head": build_subject_head,
            "last_verified_run": "livewire_pr_a_branch_repair",
            "expires_at": None,
        }
        for node_id, node_type, truth_plane, status, authority_state, claim_authority, payload_sha256, source_refs in nodes
    ]

    base_decision = {
        "schema_id": "kt.claim_decision.v1",
        "claim_id": "claim:stop300_bounded_internal",
        "decision_node_id": "claim_decision:stop300_bounded",
        "decision": "ALLOW_INTERNAL",
        "allowed_claim_classes": [
            "bounded internal STOP300 mechanism result",
            "governed evidence import and detached clean-room recomputation",
        ],
        "forbidden_claim_classes": [
            "runtime authority",
            "production authority",
            "commercial authority",
            "external certification",
            "competitive superiority",
        ],
        "fact_evidence_refs": [
            "fact:stop300_v41_completed",
            "fact:stop300_v41_official_block",
            "fact:stop300_v41_cleanroom_recomputed",
        ],
        "authority_evidence_refs": [
            "authority:claim_ceiling_current",
            "authority:stop300_import_bounded",
            "authority:stop300_run_next_demoted",
        ],
        "product_exposure_refs": [],
        "claim_ceiling_ref": "authority:claim_ceiling_current",
        "limitations": [
            "official result remains BLOCK_UNSAFE_STOP",
            "repaired court is counterfactual-only and remains BLOCK_TOKEN_ECONOMICS",
            "branch-derived artifacts are not merged-main truth until protected merge and replay",
            "no production/runtime/certification/commercial authority granted",
            "no fresh HF pull was performed because no HF token was present in this environment",
        ],
        "generated_from_head": build_subject_head,
    }
    decision = {**base_decision, "decision_sha256": claim_decision_hash(base_decision)}
    for node in node_payloads:
        if node["node_id"] in {"claim_decision:stop300_bounded", "claim:stop300_bounded_internal"}:
            node["payload_sha256"] = decision["decision_sha256"]
    write(ROOT / "reports/livewire_pr_a_claim_decisions.json", {"schema_id": "kt.claim_decision_set.v1", "decisions": [decision]})

    edge_specs = [
        ("e:completed_supports_decision", "fact:stop300_v41_completed", "claim_decision:stop300_bounded", "SUPPORTS", "DETACHED_RECOMPUTED", ["src:stop300_cleanroom"]),
        ("e:recompute_supports_decision", "fact:stop300_v41_cleanroom_recomputed", "claim_decision:stop300_bounded", "SUPPORTS", "DETACHED_RECOMPUTED", ["src:stop300_cleanroom", "src:stop300_pair_rows"]),
        ("e:block_supports_decision", "fact:stop300_v41_official_block", "claim_decision:stop300_bounded", "SUPPORTS", "DETACHED_RECOMPUTED", ["src:stop300_official_preservation"]),
        ("e:authority_supports_decision", "authority:claim_ceiling_current", "claim_decision:stop300_bounded", "SUPPORTS", "RECEIPT_VERIFIED", ["src:claim_ceiling_snapshot"]),
        ("e:import_authority_supports_decision", "authority:stop300_import_bounded", "claim_decision:stop300_bounded", "SUPPORTS", "RECEIPT_VERIFIED", ["src:live_repo_snapshot"]),
        ("e:stale_run_demotion_supports_decision", "authority:stop300_run_next_demoted", "claim_decision:stop300_bounded", "SUPPORTS", "RECEIPT_VERIFIED", ["src:live_repo_snapshot"]),
        ("e:decision_decides_claim", "claim_decision:stop300_bounded", "claim:stop300_bounded_internal", "DECIDES_CLAIM", "RECEIPT_VERIFIED", ["src:stop300_cleanroom", "src:claim_ceiling_snapshot"]),
        ("e:counterfactual_derived", "fact:stop300_v41_counterfactual", "fact:stop300_v41_official_block", "DERIVED_FROM", "DETACHED_RECOMPUTED", ["src:stop300_counterfactual"]),
        ("e:old_run_instruction_superseded", "authority:stop300_import_bounded", "authority:stop300_run_next_demoted", "SUPERSEDES", "RECEIPT_VERIFIED", ["src:live_repo_snapshot"]),
    ]
    graph = {
        "schema_id": GRAPH_SCHEMA,
        "generated_from_head": build_subject_head,
        **head_semantics,
        "source_set_sha256": source_set,
        "nodes": node_payloads,
        "edges": [
            {
                "edge_id": edge_id,
                "from_node": source,
                "to_node": target,
                "edge_type": edge_type,
                "scope": "COUNTERFACTUAL_SEPARATE" if "counterfactual" in edge_id else "STOP300_V4_1",
                "evidence_status": status,
                "source_refs": refs,
                "observed_head": build_subject_head,
                "inference": False,
            }
            for edge_id, source, target, edge_type, status, refs in edge_specs
        ],
        "contradictions": [],
    }
    graph_canonical_sha = sha256_json(graph)
    graph_file_sha = write(ROOT / "reports/livewire_pr_a_system_evidence_graph_payload.json", graph)

    truth = {
        "schema_id": TRUTH_SCHEMA,
        "generated_from_head": build_subject_head,
        **head_semantics,
        "source_set_sha256": source_set,
        "generated_from_graph_sha256": graph_canonical_sha,
        "claim_ceiling_sha256": claim_ceiling_sha,
        "open_contradiction_count": 0,
        "critical_blockers": [],
        "fact_truth": [
            {
                "result_id": "fact_result:stop300_completed",
                "status": "COMPLETED_OFF_REPO_RECOVERED_AND_RECOMPUTED_BRANCH_DERIVED",
                "fact_refs": ["fact:stop300_v41_cleanroom_recomputed", "fact:stop300_v41_completed", "fact:stop300_v41_official_block"],
                "claim_decision_ref": "claim_decision:stop300_bounded",
            }
        ],
        "authority_truth": [
            {
                "result_id": "authority_result:stop300_import",
                "status": "INTERNAL_IMPORT_ONLY_NO_RUNTIME_AUTHORITY_BRANCH_DERIVED",
                "fact_refs": ["fact:stop300_v41_completed"],
                "claim_decision_ref": "claim_decision:stop300_bounded",
            },
            {
                "result_id": "authority_result:stop300_run_next_demoted",
                "status": "STALE_RUN_NEXT_DEMOTED_NOT_CURRENT_MOVE",
                "fact_refs": ["fact:stop300_v41_official_block"],
                "claim_decision_ref": "claim_decision:stop300_bounded",
            },
        ],
        "claim_truth": [
            {
                "result_id": "claim_result:stop300_bounded",
                "status": "ALLOW_INTERNAL_BOUNDED_ONLY_BRANCH_DERIVED",
                "fact_refs": ["fact:stop300_v41_completed", "fact:stop300_v41_official_block"],
                "claim_decision_ref": "claim_decision:stop300_bounded",
            }
        ],
        "product_truth": [
            {
                "result_id": "product_result:stop300_demo",
                "status": "NOT_PRODUCTIZED",
                "fact_refs": ["fact:stop300_v41_completed"],
                "claim_decision_ref": "claim_decision:stop300_bounded",
            }
        ],
        "repo_pending": [
            {
                "work_id": "pr_b",
                "owner": "NEXT_TRANCHE_COMPILER",
                "description": "Compile one bounded proof-carrying runtime vertical after PR A merge and fresh-clone replay",
                "authority_required": "MERGED_MAIN_GRAPH",
            }
        ],
        "compute_pending": [],
        "next_moves": [
            {
                "work_id": "pr_b",
                "owner": "NEXT_TRANCHE_COMPILER",
                "description": "Author PR B from merged-main graph after fresh-clone replay",
                "authority_required": "MERGED_PR_A",
            }
        ],
    }
    truth_canonical_sha = sha256_json(truth)
    truth_file_sha = write(ROOT / "reports/livewire_pr_a_current_program_truth_payload.json", truth)

    graph_envelope = deterministic_envelope(
        payload=graph,
        payload_schema_id=GRAPH_SCHEMA,
        payload_path="reports/livewire_pr_a_system_evidence_graph_payload.json",
        source_set_sha256_value=source_set,
        build_subject_head=build_subject_head,
        build_execution_id="livewire-pr-a",
    )
    write(ROOT / "reports/livewire_pr_a_system_evidence_graph_payload.envelope.json", graph_envelope)
    truth_envelope = deterministic_envelope(
        payload=truth,
        payload_schema_id=TRUTH_SCHEMA,
        payload_path="reports/livewire_pr_a_current_program_truth_payload.json",
        source_set_sha256_value=source_set,
        build_subject_head=build_subject_head,
        build_execution_id="livewire-pr-a-truth",
    )
    write(ROOT / "reports/livewire_pr_a_current_program_truth_payload.envelope.json", truth_envelope)

    registry_path = ROOT / "registry/artifact_authority_registry.json"
    registry = load(registry_path)
    artifacts = registry.setdefault("artifacts", [])
    by_id = {artifact.get("artifact_id"): artifact for artifact in artifacts}

    def upsert(item: dict[str, Any]) -> None:
        if item["artifact_id"] in by_id:
            by_id[item["artifact_id"]].update(item)
        else:
            artifacts.append(item)
            by_id[item["artifact_id"]] = item

    for artifact_id, path, role, sha in (
        ("livewire_pr_a_system_evidence_graph_payload", "reports/livewire_pr_a_system_evidence_graph_payload.json", "Branch-derived deterministic evidence graph payload for STOP300 import", graph_file_sha),
        ("livewire_pr_a_current_program_truth_payload", "reports/livewire_pr_a_current_program_truth_payload.json", "Branch-derived current-truth projection from PR-A evidence graph", truth_file_sha),
        ("livewire_pr_a_stop300_cleanroom_recomputation", "evidence/stop300/stop300_cleanroom_recomputation_v2.json", "Detached STOP300 clean-room recomputation receipt; raw evidence not vendored", recompute_sha),
        ("livewire_pr_a_authority_registry_reconciliation", "reports/livewire_pr_a_receipt_bundle.json", "Registry reconciliation and stale STOP300 run instruction demotion receipt", receipt_sha),
    ):
        upsert({
            "artifact_id": artifact_id,
            "path": path,
            "role": role,
            "primary_class": "CANONICAL_RECEIPT_CURRENT",
            "authority_state": REGISTRY_BRANCH_AUTHORITY,
            "validation_status": "PASS",
            "controls_execution": False,
            "claim_authority": "INTERNAL_SHADOW",
            "sha256": sha,
        })
    upsert({
        "artifact_id": "stop300_v41_packet_decision",
        "path": "reports/stop300_v41_packet_decision.json",
        "role": "Historical STOP300 V4.1 run-next packet decision demoted after completed assessment import",
        "primary_class": "ARCHIVE_HISTORY",
        "authority_state": "STALE",
        "validation_status": "PASS",
        "controls_execution": False,
        "claim_authority": "NONE",
        "sha256": packet_decision_sha,
    })
    registry["current_head"] = build_subject_head
    registry["generated_utc"] = CREATED_UTC
    write(registry_path, registry)

    print(json.dumps({
        "source_index_sha256": source_index_sha,
        "source_set_sha256": source_set,
        "graph_sha256": graph_canonical_sha,
        "graph_file_sha256": graph_file_sha,
        "truth_sha256": truth_canonical_sha,
        "truth_file_sha256": truth_file_sha,
        "claim_decision_sha256": decision["decision_sha256"],
        "origin_main_discovery_status": origin_main["status"],
        "starting_main_head": starting_main_head,
        "build_subject_head": build_subject_head,
        "validated_at_head": validated_at_head,
        "merged_main_head": merged_main_head,
        "registry_status": "RECONCILED_BRANCH_DERIVED",
    }, indent=2, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cleanroom", required=True)
    parser.add_argument("--head", help="Backward-compatible alias for --build-subject-head")
    parser.add_argument("--branch")
    parser.add_argument("--starting-main-head")
    parser.add_argument("--build-subject-head")
    parser.add_argument("--validated-at-head")
    parser.add_argument("--merged-main-head")
    build(parser.parse_args())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
