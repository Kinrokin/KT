from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_post_f_truth_engine_validator_schema_and_contradiction_taxonomy_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_truth_engine_validator_schema_and_contradiction_taxonomy_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_TRUTH_ENGINE_VALIDATOR_SCHEMA_AND_CONTRADICTION_TAXONOMY_REPORT.md"

REQUIRED_BRANCH = "authoritative/post-f-truth-engine"
EXECUTION_STATUS = "PASS__POST_F_TRUTH_ENGINE_VALIDATOR_SCHEMA_AND_CONTRADICTION_TAXONOMY_BOUND"
OUTCOME = "POST_F_TRUTH_ENGINE_VALIDATOR_SCHEMA_AND_CONTRADICTION_TAXONOMY_DEFINED__FIRST_RECOMPUTE_READY"
NEXT_MOVE = "IMPLEMENT_POST_F_TRUTH_ENGINE_VALIDATOR_AND_RECOMPUTE_TRANCHE"


def _current_branch_name(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    branch = result.stdout.strip()
    return branch or "UNKNOWN_BRANCH"


def _git_status_porcelain(root: Path) -> str:
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout


def _git_rev_parse(root: Path, ref: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", ref],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout.strip()


def _git_merge_base(root: Path, left: str, right: str) -> str:
    result = subprocess.run(
        ["git", "merge-base", left, right],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout.strip()


def _emission_schemas() -> Dict[str, Any]:
    return {
        "authority_graph": {
            "schema_id": "kt.operator.cohort0_post_f_truth_engine_authority_graph.v1",
            "type": "object",
            "required_fields": [
                "schema_id",
                "generated_utc",
                "branch_ref",
                "winning_authority_sources",
                "rejected_conflicting_sources",
                "precedence_edges",
            ],
            "entry_schema": {
                "winning_authority_sources[]": ["source_class_id", "rank", "ref", "drives_live_truth"],
                "rejected_conflicting_sources[]": ["source_class_id", "ref", "rejection_reason", "contradiction_class_id"],
                "precedence_edges[]": ["from_ref", "to_ref", "edge_type", "justification"],
            },
            "ordering_rule": "winning_authority_sources by ascending rank then ref; edges lexicographic by from_ref/to_ref",
        },
        "posture_index": {
            "schema_id": "kt.operator.cohort0_post_f_truth_engine_posture_index.v1",
            "type": "object",
            "required_fields": [
                "schema_id",
                "generated_utc",
                "theorem_truth_posture",
                "product_truth_posture",
                "merge_truth_posture",
                "package_truth_posture",
                "winning_source_refs",
            ],
            "entry_schema": {
                "winning_source_refs": ["theorem_truth", "product_truth", "merge_truth", "package_truth"],
            },
            "ordering_rule": "fixed key ordering in theorem/product/merge/package sequence",
        },
        "contradiction_ledger": {
            "schema_id": "kt.operator.cohort0_post_f_truth_engine_contradiction_ledger.v1",
            "type": "object",
            "required_fields": [
                "schema_id",
                "generated_utc",
                "status",
                "blocking_contradiction_count",
                "advisory_contradiction_count",
                "contradictions",
            ],
            "entry_schema": {
                "contradictions[]": [
                    "contradiction_id",
                    "class_id",
                    "severity",
                    "triggered_by_refs",
                    "governing_precedence_class_id",
                    "halt_behavior",
                    "resolution_path",
                ],
            },
            "ordering_rule": "blocking contradictions first by severity desc then contradiction_id; advisory contradictions after",
        },
        "stale_source_quarantine_list": {
            "schema_id": "kt.operator.cohort0_post_f_truth_engine_stale_source_quarantine_list.v1",
            "type": "object",
            "required_fields": [
                "schema_id",
                "generated_utc",
                "quarantine_candidate_count",
                "quarantine_candidates",
            ],
            "entry_schema": {
                "quarantine_candidates[]": ["ref", "reason", "source_class_id", "replacement_ref"],
            },
            "ordering_rule": "lexicographic by ref",
        },
        "recompute_receipt": {
            "schema_id": "kt.operator.cohort0_post_f_truth_engine_recompute_receipt.v1",
            "type": "object",
            "required_fields": [
                "schema_id",
                "generated_utc",
                "status",
                "branch_ref",
                "derived_from_contract_id",
                "authority_graph_ref",
                "posture_index_ref",
                "contradiction_ledger_ref",
                "stale_source_quarantine_list_ref",
                "blocking_contradiction_count",
                "next_lawful_move",
            ],
            "entry_schema": {},
            "ordering_rule": "stable key ordering; refs absolute-resolved in emitted receipt",
        },
    }


def _contradiction_taxonomy() -> Dict[str, Any]:
    return {
        "stale_vs_live": {
            "trigger_condition": "A stale receipt or packet claims a stronger or different posture than the current winning canonical live source.",
            "severity": "blocking_high",
            "halt_behavior": "HALT_RECOMPUTE",
            "resolution_path": "Quarantine stale source and rerun derivation against the newer winning source.",
            "governing_precedence_rule": "canonical_post_merge_repo_authority outranks stale historical or branch-local claims",
        },
        "historical_vs_superseded": {
            "trigger_condition": "A historical checkpoint attempts to outrank an explicit supersession or newer canonical receipt.",
            "severity": "blocking_high",
            "halt_behavior": "HALT_RECOMPUTE",
            "resolution_path": "Emit supersession conflict and retain historical source as lineage-only.",
            "governing_precedence_rule": "historical_and_superseded_lineage never drives live truth",
        },
        "package_vs_repo": {
            "trigger_condition": "A deferred package artifact is selected as a live truth driver or wins a precedence tie.",
            "severity": "blocking_critical",
            "halt_behavior": "HALT_RECOMPUTE",
            "resolution_path": "Reject package surface and require a separate package-promotion court before reuse.",
            "governing_precedence_rule": "deferred_package_and_non_authoritative_prep cannot drive live truth",
        },
        "branch_local_vs_canonical": {
            "trigger_condition": "A branch-local source outranks or contradicts canonical main-level authority after merge.",
            "severity": "blocking_high",
            "halt_behavior": "HALT_RECOMPUTE",
            "resolution_path": "Preserve branch-local source as branch evidence only and defer any change to a new authoritative court.",
            "governing_precedence_rule": "canonical_post_merge_repo_authority outranks branch-local outputs",
        },
        "theorem_vs_product": {
            "trigger_condition": "Derived theorem posture and derived product posture imply incompatible live states.",
            "severity": "blocking_high",
            "halt_behavior": "HALT_RECOMPUTE_AND_REQUIRE_NEW_COURT",
            "resolution_path": "Open a dedicated reconciliation court because theorem and product layers cannot be silently reinterpreted.",
            "governing_precedence_rule": "canonical_theorem_and_product_truth must remain internally coherent",
        },
        "prep_lane_overreach": {
            "trigger_condition": "A non-authoritative prep lane publishes or implies live authority beyond its declared scope.",
            "severity": "blocking_medium",
            "halt_behavior": "HALT_RECOMPUTE",
            "resolution_path": "Demote prep output to advisory-only and require explicit promotion before reuse.",
            "governing_precedence_rule": "deferred_package_and_non_authoritative_prep never drives live truth",
        },
        "missing_authority_source": {
            "trigger_condition": "An emitted posture or contradiction result cannot name its authoritative winning source.",
            "severity": "blocking_critical",
            "halt_behavior": "HALT_RECOMPUTE",
            "resolution_path": "Reject emission and rerun only after source provenance is complete.",
            "governing_precedence_rule": "Every emitted output must cite a winning source and rejected conflicting sources",
        },
    }


def _validator_behavior(root: Path) -> Dict[str, Any]:
    return {
        "input_set": {
            "canonical_inputs": [
                common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_closeout_receipt.json").as_posix(),
                common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_branch_snapshot.json").as_posix(),
                common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_validator_authority_receipt.json").as_posix(),
                common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_successor_master_orchestrator_receipt.json").as_posix(),
                common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_final_summary_receipt.json").as_posix(),
            ],
            "governance_inputs": [
                common.resolve_path(root, "KT_PROD_CLEANROOM/governance/truth_engine_contract.json").as_posix(),
                common.resolve_path(root, "KT_PROD_CLEANROOM/governance/posture_contract.json").as_posix(),
                common.resolve_path(root, "KT_PROD_CLEANROOM/governance/settled_truth_source_contract.json").as_posix(),
                common.resolve_path(root, "KT_PROD_CLEANROOM/governance/truth_supersession_rules.json").as_posix(),
                common.resolve_path(root, "KT_PROD_CLEANROOM/reports/reporting_integrity_contract.json").as_posix(),
            ],
        },
        "canonicalization_rules": {
            "encoding": "utf-8",
            "json_serialization": "stable key ordering with newline-terminated output",
            "path_normalization": "absolute resolved refs in receipts, repo-relative keys in schemas",
            "list_ordering": "lexicographic unless schema defines explicit severity/rank ordering",
        },
        "precedence_resolution": {
            "winning_rule": "lowest source_precedence rank wins",
            "tie_rule": "same-rank disagreement is a blocking contradiction",
            "lineage_rule": "non-driving classes may explain but may never decide live posture",
        },
        "exclusion_handling": {
            "drop_from_winner_set": [
                "deferred package artifacts",
                "non-authoritative prep lanes",
                "superseded historical checkpoints",
                "smoke-only artifacts",
            ],
            "quarantine_output_required_on_exclusion": True,
        },
        "deterministic_output_ordering": {
            "authority_graph": "rank asc then ref",
            "posture_index": "fixed theorem/product/merge/package order",
            "contradiction_ledger": "blocking first by severity desc then contradiction_id",
            "stale_source_quarantine_list": "ref asc",
        },
        "failure_codes": [
            "MISSING_CANONICAL_SOURCE",
            "PRECEDENCE_TIE_BLOCK",
            "PACKAGE_SURFACE_OVERREACH",
            "PREP_LANE_OVERREACH",
            "MISSING_SOURCE_PROVENANCE",
            "THEOREM_PRODUCT_CONTRADICTION",
        ],
    }


def _first_recompute_court(root: Path) -> Dict[str, Any]:
    return {
        "branch_scope": REQUIRED_BRANCH,
        "reads": [
            common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_closeout_receipt.json").as_posix(),
            common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_branch_snapshot.json").as_posix(),
            common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_validator_authority_receipt.json").as_posix(),
            common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_validator_contract_receipt.json").as_posix(),
            common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_successor_master_orchestrator_receipt.json").as_posix(),
            common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_final_summary_receipt.json").as_posix(),
        ],
        "emits": [
            "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_authority_graph.json",
            "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_posture_index.json",
            "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_ledger.json",
            "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_stale_source_quarantine_list.json",
            "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_recompute_receipt.json",
        ],
        "blocking_contradictions": [
            "stale_vs_live",
            "historical_vs_superseded",
            "package_vs_repo",
            "branch_local_vs_canonical",
            "theorem_vs_product",
            "prep_lane_overreach",
            "missing_authority_source",
        ],
        "advisory_until_pr15_lands": [
            "remote canonical branch still pending PR #15 merge",
            "branch-local recompute may describe canonical intent but cannot publish remote-main settlement yet",
        ],
    }


def build_outputs(
    *,
    branch_name: str,
    branch_head: str,
    main_head: str,
    authority_packet: Dict[str, Any],
    contract_packet: Dict[str, Any],
) -> Dict[str, Dict[str, Any] | str]:
    root = repo_root()
    emission_schemas = _emission_schemas()
    contradiction_taxonomy = _contradiction_taxonomy()
    packet = {
        "schema_id": "kt.operator.cohort0_post_f_truth_engine_validator_schema_and_contradiction_taxonomy_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "outcome": OUTCOME,
        "claim_boundary": (
            "This packet defines validator schemas, contradiction taxonomy, validator behavior, and first-recompute court boundaries only. "
            "It does not execute recomputation and does not widen package or prep authority."
        ),
        "authority_header": {
            "authoritative_lane_branch": branch_name,
            "authoritative_lane_branch_head": branch_head,
            "canonical_parent_main_head": main_head,
            "package_promotion_still_deferred": bool(authority_packet.get("authority_header", {}).get("package_promotion_still_deferred", False)),
        },
        "emission_surface_schemas": emission_schemas,
        "contradiction_taxonomy": contradiction_taxonomy,
        "validator_behavior": _validator_behavior(root),
        "first_recompute_court": _first_recompute_court(root),
        "source_refs": common.output_ref_dict(
            authority_packet=common.resolve_path(
                root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_validator_authority_packet.json"
            ),
            contract_packet=common.resolve_path(
                root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_validator_contract_packet.json"
            ),
            truth_engine_py=common.resolve_path(root, "KT_PROD_CLEANROOM/tools/operator/truth_engine.py"),
        ),
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_truth_engine_validator_schema_and_contradiction_taxonomy_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "outcome": OUTCOME,
        "emission_surface_schema_count": len(emission_schemas),
        "contradiction_taxonomy_class_count": len(contradiction_taxonomy),
        "validator_failure_code_count": len(packet["validator_behavior"]["failure_codes"]),
        "next_lawful_move": NEXT_MOVE,
    }
    report = common.report_lines(
        "Cohort0 Post-F Truth Engine Validator Schema And Contradiction Taxonomy Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Outcome: `{OUTCOME}`",
            f"- Emission surface schemas: `{len(emission_schemas)}`",
            f"- Contradiction taxonomy classes: `{len(contradiction_taxonomy)}`",
            f"- Validator failure codes: `{len(packet['validator_behavior']['failure_codes'])}`",
            "- First recompute court is frozen as branch-authoritative and remote-main advisory until PR #15 lands.",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    authority_packet_path: Path,
    contract_packet_path: Path,
    contract_receipt_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: validator schema/taxonomy packet must run on {REQUIRED_BRANCH}, got {branch_name}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: validator schema/taxonomy packet requires a clean worktree")

    authority_packet = common.load_json_required(root, authority_packet_path, label="truth-engine authority packet")
    contract_packet = common.load_json_required(root, contract_packet_path, label="truth-engine contract packet")
    contract_receipt = common.load_json_required(root, contract_receipt_path, label="truth-engine contract receipt")
    common.ensure_pass(authority_packet, label="truth-engine authority packet")
    common.ensure_pass(contract_packet, label="truth-engine contract packet")
    common.ensure_pass(contract_receipt, label="truth-engine contract receipt")

    if str(contract_receipt.get("next_lawful_move", "")).strip() != "AUTHOR_POST_F_TRUTH_ENGINE_VALIDATOR_SCHEMA_AND_CONTRADICTION_TAXONOMY_PACKET":
        raise RuntimeError("FAIL_CLOSED: truth-engine contract does not authorize the validator schema/taxonomy packet")

    main_head = _git_rev_parse(root, "main")
    if _git_merge_base(root, "main", "HEAD") != main_head:
        raise RuntimeError("FAIL_CLOSED: authoritative truth-engine branch must remain based on current main without divergence")

    outputs = build_outputs(
        branch_name=branch_name,
        branch_head=_git_rev_parse(root, "HEAD"),
        main_head=main_head,
        authority_packet=authority_packet,
        contract_packet=contract_packet,
    )
    common.write_outputs(
        packet_path=(reports_root / OUTPUT_PACKET).resolve(),
        receipt_path=(reports_root / OUTPUT_RECEIPT).resolve(),
        report_path=(reports_root / OUTPUT_REPORT).resolve(),
        packet=outputs["packet"],
        receipt=outputs["receipt"],
        report_text=str(outputs["report"]),
    )
    return {"outcome": OUTCOME, "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(), "next_lawful_move": NEXT_MOVE}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Bind the truth-engine validator schema and contradiction taxonomy packet.")
    parser.add_argument(
        "--authority-packet",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_validator_authority_packet.json",
    )
    parser.add_argument(
        "--contract-packet",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_validator_contract_packet.json",
    )
    parser.add_argument(
        "--contract-receipt",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_validator_contract_receipt.json",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        authority_packet_path=common.resolve_path(root, args.authority_packet),
        contract_packet_path=common.resolve_path(root, args.contract_packet),
        contract_receipt_path=common.resolve_path(root, args.contract_receipt),
    )
    print(result["outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
