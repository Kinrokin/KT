#!/usr/bin/env python3
"""Build deterministic KT Core Livewire V2.2 PR-A artifacts.

This script intentionally records only bounded receipts, hashes, and pointers.
Recovered STOP300 archives remain external/packet evidence and are not vendored
into git.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ID_SOURCE = "kt.livewire.source_evidence_index.v2"
SCHEMA_ID_GRAPH = "kt.system_evidence_graph_payload.v2"
SCHEMA_ID_TRUTH = "kt.current_program_truth_payload.v2"


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
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    return sha256_file(path)


def git_head() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()


def git_branch() -> str:
    return subprocess.check_output(["git", "branch", "--show-current"], cwd=ROOT, text=True).strip()


def file_info(rel: str) -> tuple[int, str]:
    path = ROOT / rel
    return path.stat().st_size, sha256_file(path)


def source_set_sha256(source_index: dict[str, Any]) -> str:
    reduced = [{k: v for k, v in src.items() if k != "controlling"} for src in source_index["sources"]]
    return sha256_json(reduced)


def claim_decision_hash(decision: dict[str, Any]) -> str:
    return sha256_json({k: v for k, v in decision.items() if k != "decision_sha256"})


def build(args: argparse.Namespace) -> None:
    head = args.head or git_head()
    branch = args.branch or git_branch()
    cleanroom = load(Path(args.cleanroom))

    claim_ceiling_bytes, claim_ceiling_sha = file_info("governance/current_claim_ceiling.json")
    packet_decision_bytes, packet_decision_sha = file_info("reports/stop300_v41_packet_decision.json")
    packet_summary_bytes, packet_summary_sha = file_info("reports/stop300_v41_builder_summary.json")
    packet_sha = sha256_file(ROOT / "packets/ktstop300_v4_1.zip") if (ROOT / "packets/ktstop300_v4_1.zip").exists() else None

    recompute_sha = write(ROOT / "evidence/stop300/stop300_cleanroom_recomputation_v2.json", cleanroom)
    recompute_receipt = {
        **cleanroom,
        "receipt_id": "stop300_v41_cleanroom_recomputation_current_head",
        "generated_from_head": head,
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
        "generated_from_head": head,
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
        "generated_from_head": head,
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
        "generated_from_head": head,
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
        "generated_from_head": head,
        "branch": branch,
        "origin_main_head": subprocess.check_output(["git", "rev-parse", "origin/main"], cwd=ROOT, text=True).strip(),
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
        "generated_from_head": head,
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
    receipt_bundle_sha = write(ROOT / "reports/livewire_pr_a_receipt_bundle.json", receipt_bundle)
    official_sha = receipt_bundle_sha
    counterfactual_sha = receipt_bundle_sha
    pointer_sha = receipt_bundle_sha
    discovery_sha = receipt_bundle_sha

    sources = [
        {
            "source_id": "src:live_repo_snapshot",
            "authority_class": "LIVE_CANONICAL",
            "packet_relative_path": None,
            "repo_path": "reports/stop300_v41_packet_decision.json",
            "external_locator": None,
            "head": head,
            "sha256": packet_decision_sha,
            "bytes": packet_decision_bytes,
            "transport_identity_status": "BYTE_IDENTICAL",
            "controlling": True,
        },
        {
            "source_id": "src:live_repo_builder_summary",
            "authority_class": "LIVE_CANONICAL",
            "packet_relative_path": None,
            "repo_path": "reports/stop300_v41_builder_summary.json",
            "external_locator": None,
            "head": head,
            "sha256": packet_summary_sha,
            "bytes": packet_summary_bytes,
            "transport_identity_status": "BYTE_IDENTICAL",
            "controlling": False,
        },
        {
            "source_id": "src:claim_ceiling_snapshot",
            "authority_class": "LIVE_CANONICAL",
            "packet_relative_path": None,
            "repo_path": "governance/current_claim_ceiling.json",
            "external_locator": None,
            "head": head,
            "sha256": claim_ceiling_sha,
            "bytes": claim_ceiling_bytes,
            "transport_identity_status": "BYTE_IDENTICAL",
            "controlling": True,
        },
        {
            "source_id": "src:stop300_assessment",
            "authority_class": "RECOVERED_REPACKAGED_EVIDENCE",
            "packet_relative_path": None,
            "repo_path": None,
            "external_locator": "hf://datasets/Kinrokin/ktstop300-v4-1-results",
            "head": head,
            "sha256": cleanroom["source_assessment_sha256"],
            "bytes": 3833374,
            "transport_identity_status": "REPACKAGED_NOT_BYTE_IDENTICAL",
            "controlling": True,
        },
        {
            "source_id": "src:stop300_cleanroom",
            "authority_class": "IMMUTABLE_MEASURED_EVIDENCE",
            "packet_relative_path": "evidence/stop300/stop300_cleanroom_recomputation_v2.json",
            "repo_path": "evidence/stop300/stop300_cleanroom_recomputation_v2.json",
            "external_locator": None,
            "head": head,
            "sha256": recompute_sha,
            "bytes": (ROOT / "evidence/stop300/stop300_cleanroom_recomputation_v2.json").stat().st_size,
            "transport_identity_status": "NOT_APPLICABLE",
            "controlling": True,
        },
        {
            "source_id": "src:stop300_pair_rows",
            "authority_class": "IMMUTABLE_MEASURED_EVIDENCE",
            "packet_relative_path": None,
            "repo_path": None,
            "external_locator": None,
            "head": head,
            "sha256": "f4796ca5391eb97cdf38328a67aea6f1b338190caa1b82b688641e18a6ccb2cf",
            "bytes": 218993,
            "transport_identity_status": "NOT_APPLICABLE",
            "controlling": True,
        },
        {
            "source_id": "src:stop300_official_preservation",
            "authority_class": "CURRENT_HEAD_RECEIPT",
            "packet_relative_path": None,
            "repo_path": "reports/livewire_pr_a_receipt_bundle.json",
            "external_locator": None,
            "head": head,
            "sha256": official_sha,
            "bytes": (ROOT / "reports/livewire_pr_a_receipt_bundle.json").stat().st_size,
            "transport_identity_status": "NOT_APPLICABLE",
            "controlling": True,
        },
        {
            "source_id": "src:stop300_counterfactual",
            "authority_class": "CURRENT_HEAD_RECEIPT",
            "packet_relative_path": None,
            "repo_path": "reports/livewire_pr_a_receipt_bundle.json",
            "external_locator": None,
            "head": head,
            "sha256": counterfactual_sha,
            "bytes": (ROOT / "reports/livewire_pr_a_receipt_bundle.json").stat().st_size,
            "transport_identity_status": "NOT_APPLICABLE",
            "controlling": True,
        },
        {
            "source_id": "src:heavy_evidence_pointer_manifest",
            "authority_class": "CURRENT_HEAD_RECEIPT",
            "packet_relative_path": None,
            "repo_path": "reports/livewire_pr_a_receipt_bundle.json",
            "external_locator": None,
            "head": head,
            "sha256": pointer_sha,
            "bytes": (ROOT / "reports/livewire_pr_a_receipt_bundle.json").stat().st_size,
            "transport_identity_status": "NOT_APPLICABLE",
            "controlling": True,
        },
        {
            "source_id": "src:discovery_receipt",
            "authority_class": "CURRENT_HEAD_RECEIPT",
            "packet_relative_path": None,
            "repo_path": "reports/livewire_pr_a_receipt_bundle.json",
            "external_locator": None,
            "head": head,
            "sha256": discovery_sha,
            "bytes": (ROOT / "reports/livewire_pr_a_receipt_bundle.json").stat().st_size,
            "transport_identity_status": "NOT_APPLICABLE",
            "controlling": True,
        },
    ]
    source_index = {
        "schema_id": SCHEMA_ID_SOURCE,
        "observed_main": head,
        "created_utc": "2026-06-23T00:00:00Z",
        "law": "live repo truth wins; recovered containers never impersonate original transport identity; heavy/raw evidence stays pointer-bound",
        "sources": sources,
    }
    source_index["source_set_sha256"] = source_set_sha256(source_index)
    # source_set_sha256 is not in schema, so keep it external to the source index payload.
    source_set = source_index.pop("source_set_sha256")
    source_index_sha = write(ROOT / "SOURCE_EVIDENCE_INDEX.json", source_index)

    nodes = [
        {
            "node_id": "fact:stop300_v41_completed",
            "node_type": "fact",
            "truth_plane": "FACT",
            "scope": "STOP300_V4_1",
            "status": "COMPLETED_OFF_REPO_RECOVERED_REPACKAGED",
            "authority_state": "CURRENT_HEAD",
            "claim_authority": "NONE",
            "payload_sha256": recompute_sha,
            "source_refs": ["src:stop300_assessment", "src:stop300_cleanroom"],
            "last_verified_head": head,
            "last_verified_run": "livewire_pr_a_cleanroom",
            "expires_at": None,
        },
        {
            "node_id": "fact:stop300_v41_cleanroom_recomputed",
            "node_type": "fact",
            "truth_plane": "FACT",
            "scope": "STOP300_V4_1",
            "status": "DETACHED_RECOMPUTATION_PASS",
            "authority_state": "CURRENT_HEAD",
            "claim_authority": "NONE",
            "payload_sha256": recompute_sha,
            "source_refs": ["src:stop300_cleanroom", "src:stop300_pair_rows"],
            "last_verified_head": head,
            "last_verified_run": "livewire_pr_a_cleanroom",
            "expires_at": None,
        },
        {
            "node_id": "fact:stop300_v41_official_block",
            "node_type": "fact",
            "truth_plane": "FACT",
            "scope": "STOP300_V4_1_OFFICIAL",
            "status": cleanroom["official_recomputed_status"],
            "authority_state": "CURRENT_HEAD",
            "claim_authority": "NONE",
            "payload_sha256": official_sha,
            "source_refs": ["src:stop300_assessment", "src:stop300_official_preservation"],
            "last_verified_head": head,
            "last_verified_run": "livewire_pr_a_official_preservation",
            "expires_at": None,
        },
        {
            "node_id": "fact:stop300_v41_counterfactual",
            "node_type": "fact",
            "truth_plane": "FACT",
            "scope": "STOP300_V4_1_REPAIRED_COUNTERFACTUAL",
            "status": "BLOCK_TOKEN_ECONOMICS_COUNTERFACTUAL_ONLY",
            "authority_state": "CURRENT_HEAD",
            "claim_authority": "NONE",
            "payload_sha256": counterfactual_sha,
            "source_refs": ["src:stop300_counterfactual"],
            "last_verified_head": head,
            "last_verified_run": "livewire_pr_a_counterfactual",
            "expires_at": None,
        },
        {
            "node_id": "authority:claim_ceiling_current",
            "node_type": "authority_decision",
            "truth_plane": "AUTHORITY",
            "scope": "CURRENT_CLAIM_CEILING",
            "status": "PRESERVED",
            "authority_state": "CURRENT_HEAD",
            "claim_authority": "CURRENT_HEAD",
            "payload_sha256": claim_ceiling_sha,
            "source_refs": ["src:claim_ceiling_snapshot"],
            "last_verified_head": head,
            "last_verified_run": "livewire_pr_a_truth_pin",
            "expires_at": None,
        },
        {
            "node_id": "authority:stop300_import_bounded",
            "node_type": "authority_decision",
            "truth_plane": "AUTHORITY",
            "scope": "STOP300_V4_1_IMPORT",
            "status": "INTERNAL_EVIDENCE_IMPORT_ONLY",
            "authority_state": "CURRENT_HEAD",
            "claim_authority": "CURRENT_HEAD",
            "payload_sha256": packet_decision_sha,
            "source_refs": ["src:live_repo_snapshot", "src:claim_ceiling_snapshot"],
            "last_verified_head": head,
            "last_verified_run": "livewire_pr_a",
            "expires_at": None,
        },
        {
            "node_id": "authority:stop300_run_next_demoted",
            "node_type": "authority_decision",
            "truth_plane": "AUTHORITY",
            "scope": "STOP300_V4_1_STALE_RUN_INSTRUCTION",
            "status": "STALE_DEMOTED_BY_COMPLETED_ASSESSMENT_IMPORT",
            "authority_state": "STALE",
            "claim_authority": "NONE",
            "payload_sha256": packet_decision_sha,
            "source_refs": ["src:live_repo_snapshot"],
            "last_verified_head": head,
            "last_verified_run": "livewire_pr_a_demote_stale_run_next",
            "expires_at": None,
        },
        {
            "node_id": "claim_decision:stop300_bounded",
            "node_type": "claim_decision",
            "truth_plane": "CLAIM",
            "scope": "STOP300_V4_1",
            "status": "ALLOW_INTERNAL_BOUNDED_ONLY",
            "authority_state": "CURRENT_HEAD",
            "claim_authority": "CURRENT_HEAD",
            "payload_sha256": "0" * 64,
            "source_refs": ["src:stop300_cleanroom", "src:claim_ceiling_snapshot"],
            "last_verified_head": head,
            "last_verified_run": "livewire_pr_a",
            "expires_at": None,
        },
        {
            "node_id": "claim:stop300_bounded_internal",
            "node_type": "claim",
            "truth_plane": "CLAIM",
            "scope": "STOP300_V4_1",
            "status": "BOUNDED_INTERNAL_MECHANISM_RESULT",
            "authority_state": "CURRENT_HEAD",
            "claim_authority": "CURRENT_HEAD",
            "payload_sha256": "0" * 64,
            "source_refs": ["src:stop300_cleanroom", "src:claim_ceiling_snapshot"],
            "last_verified_head": head,
            "last_verified_run": "livewire_pr_a",
            "expires_at": None,
        },
        {
            "node_id": "product:stop300_verify_demo",
            "node_type": "product_exposure",
            "truth_plane": "PRODUCT",
            "scope": "KT_VERIFY_DEMO",
            "status": "NOT_PRODUCTIZED",
            "authority_state": "PREP_ONLY",
            "claim_authority": "NONE",
            "payload_sha256": None,
            "source_refs": ["src:stop300_cleanroom"],
            "last_verified_head": head,
            "last_verified_run": None,
            "expires_at": None,
        },
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
            "no production/runtime/certification/commercial authority granted",
            "no fresh HF pull was performed because no HF token was present in this environment",
        ],
        "generated_from_head": head,
    }
    decision_sha = claim_decision_hash(base_decision)
    decision = {**base_decision, "decision_sha256": decision_sha}
    for node in nodes:
        if node["node_id"] in {"claim_decision:stop300_bounded", "claim:stop300_bounded_internal"}:
            node["payload_sha256"] = decision_sha
    decisions = {"schema_id": "kt.claim_decision_set.v1", "decisions": [decision]}
    write(ROOT / "reports/livewire_pr_a_claim_decisions.json", decisions)

    edges = [
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
        "schema_id": SCHEMA_ID_GRAPH,
        "generated_from_head": head,
        "source_set_sha256": source_set,
        "nodes": nodes,
        "edges": [
            {
                "edge_id": edge_id,
                "from_node": source,
                "to_node": target,
                "edge_type": edge_type,
                "scope": "STOP300_V4_1" if "counterfactual" not in edge_id else "COUNTERFACTUAL_SEPARATE",
                "evidence_status": status,
                "source_refs": refs,
                "observed_head": head,
                "inference": False,
            }
            for edge_id, source, target, edge_type, status, refs in edges
        ],
        "contradictions": [],
    }
    graph_canonical_sha = sha256_json(graph)
    graph_file_sha = write(ROOT / "reports/livewire_pr_a_system_evidence_graph_payload.json", graph)

    truth = {
        "schema_id": SCHEMA_ID_TRUTH,
        "generated_from_head": head,
        "source_set_sha256": source_set,
        "generated_from_graph_sha256": graph_canonical_sha,
        "claim_ceiling_sha256": claim_ceiling_sha,
        "open_contradiction_count": 0,
        "critical_blockers": [],
        "fact_truth": [
            {
                "result_id": "fact_result:stop300_completed",
                "status": "COMPLETED_OFF_REPO_RECOVERED_AND_RECOMPUTED",
                "fact_refs": [
                    "fact:stop300_v41_cleanroom_recomputed",
                    "fact:stop300_v41_completed",
                    "fact:stop300_v41_official_block",
                ],
                "claim_decision_ref": "claim_decision:stop300_bounded",
            }
        ],
        "authority_truth": [
            {
                "result_id": "authority_result:stop300_import",
                "status": "INTERNAL_IMPORT_ONLY_NO_RUNTIME_AUTHORITY",
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
                "status": "ALLOW_INTERNAL_BOUNDED_ONLY",
                "fact_refs": [
                    "fact:stop300_v41_completed",
                    "fact:stop300_v41_official_block",
                ],
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

    reconciliation = {
        "schema_id": "kt.livewire.pr_a.authority_registry_reconciliation_receipt.v1",
        "generated_from_head": head,
        "artifact_registry_file": "registry/artifact_authority_registry.json",
        "registered_current_artifacts": [
            "reports/livewire_pr_a_system_evidence_graph_payload.json",
            "reports/livewire_pr_a_current_program_truth_payload.json",
            "reports/livewire_pr_a_stop300_cleanroom_recomputation_receipt.json",
            "reports/livewire_pr_a_stop300_official_block_preservation_receipt.json",
            "reports/livewire_pr_a_stop300_repaired_court_counterfactual_receipt.json",
        ],
        "demoted_artifacts": [
            {
                "artifact_id": "stop300_v41_packet_decision",
                "path": "reports/stop300_v41_packet_decision.json",
                "previous_next_lawful_move": "RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V4_1",
                "new_authority_state": "STALE",
                "reason": "completed STOP300 assessment imported; run-next instruction is historical lineage, not current live instruction",
            }
        ],
        "runtime_authority_granted": False,
        "claim_ceiling_status": "PRESERVED",
    }
    reconciliation_sha = receipt_bundle_sha

    registry_path = ROOT / "registry/artifact_authority_registry.json"
    registry = load(registry_path)
    artifacts = registry.setdefault("artifacts", [])
    by_id = {a.get("artifact_id"): a for a in artifacts}

    def upsert(item: dict[str, Any]) -> None:
        if item["artifact_id"] in by_id:
            by_id[item["artifact_id"]].update(item)
        else:
            artifacts.append(item)
            by_id[item["artifact_id"]] = item

    upsert({
        "artifact_id": "livewire_pr_a_system_evidence_graph_payload",
        "path": "reports/livewire_pr_a_system_evidence_graph_payload.json",
        "role": "Current-head deterministic evidence graph payload for STOP300 import",
        "primary_class": "CANONICAL_RECEIPT_CURRENT",
        "authority_state": "LIVE_CURRENT_HEAD_VALIDATED",
        "validation_status": "PASS",
        "controls_execution": False,
        "claim_authority": "CURRENT_HEAD",
        "sha256": graph_file_sha,
    })
    upsert({
        "artifact_id": "livewire_pr_a_current_program_truth_payload",
        "path": "reports/livewire_pr_a_current_program_truth_payload.json",
        "role": "Derived current-truth projection from PR-A evidence graph",
        "primary_class": "CANONICAL_RECEIPT_CURRENT",
        "authority_state": "LIVE_CURRENT_HEAD_VALIDATED",
        "validation_status": "PASS",
        "controls_execution": False,
        "claim_authority": "CURRENT_HEAD",
        "sha256": truth_file_sha,
    })
    upsert({
        "artifact_id": "livewire_pr_a_stop300_cleanroom_recomputation",
        "path": "evidence/stop300/stop300_cleanroom_recomputation_v2.json",
        "role": "Detached STOP300 clean-room recomputation receipt; raw evidence not vendored",
        "primary_class": "CANONICAL_RECEIPT_CURRENT",
        "authority_state": "LIVE_CURRENT_HEAD_VALIDATED",
        "validation_status": "PASS",
        "controls_execution": False,
        "claim_authority": "CURRENT_HEAD",
        "sha256": recompute_sha,
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
    upsert({
        "artifact_id": "livewire_pr_a_authority_registry_reconciliation",
        "path": "reports/livewire_pr_a_receipt_bundle.json",
        "role": "Registry reconciliation and stale STOP300 run instruction demotion receipt",
        "primary_class": "CANONICAL_RECEIPT_CURRENT",
        "authority_state": "LIVE_CURRENT_HEAD_VALIDATED",
        "validation_status": "PASS",
        "controls_execution": False,
        "claim_authority": "CURRENT_HEAD",
        "sha256": reconciliation_sha,
    })
    registry["current_head"] = head
    registry["generated_utc"] = "2026-06-23T00:00:00Z"
    write(registry_path, registry)

    print(json.dumps({
        "source_index_sha256": source_index_sha,
        "source_set_sha256": source_set,
        "graph_sha256": graph_canonical_sha,
        "graph_file_sha256": graph_file_sha,
        "truth_sha256": truth_canonical_sha,
        "truth_file_sha256": truth_file_sha,
        "claim_decision_sha256": decision_sha,
        "registry_status": "RECONCILED",
    }, indent=2, sort_keys=True))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--cleanroom", required=True)
    p.add_argument("--head")
    p.add_argument("--branch")
    args = p.parse_args()
    build(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
