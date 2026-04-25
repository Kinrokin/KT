from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import adapter_lifecycle_law_validate as adapter_validate
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


OUTPUT_TRUST_ZONE_PACKET = "cohort0_post_f_parallel_trust_zone_boundary_scope_packet.json"
OUTPUT_TRUTH_ENGINE_PACKET = "cohort0_post_f_parallel_truth_engine_scope_packet.json"
OUTPUT_PROOF_LAW_PACKET = "cohort0_post_f_parallel_residual_proof_law_hardening_packet.json"
OUTPUT_UPPER_STACK_PACKET = "cohort0_post_f_parallel_upper_stack_ratification_scope_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_parallel_prep_scaffold_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_PARALLEL_PREP_SCAFFOLD_REPORT.md"

REQUIRED_WORKING_BRANCH = "expansion/post-f-track-01"
EXECUTION_STATUS = "PASS__POST_F_PARALLEL_PREP_SCAFFOLDS_BOUND"
OUTCOME = "POST_F_PARALLEL_PREP_SCAFFOLDS_BOUND__NON_AUTHORITATIVE_OUTPUTS_ONLY"


def _current_branch_name(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
    except Exception:
        return "UNKNOWN_BRANCH"
    branch = result.stdout.strip()
    return branch or "UNKNOWN_BRANCH"


def _current_head(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout.strip()


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


def _trust_zone_packet(*, root: Path, matrix_packet: Dict[str, Any], verdict_receipt: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_post_f_parallel_trust_zone_boundary_scope_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "lane_id": "trust_zone_boundary_purification_scaffold",
        "lane_status": "AUTHORIZED__NON_AUTHORITATIVE_PREP_ONLY",
        "claim_boundary": "Prep-only trust-zone and boundary packet. It does not change live authority or canonical promotion status.",
        "trust_zone_registry": [
            {
                "zone_id": "canonical_live_truth",
                "boundary": "Live Track 01/02/03 summaries, successor/Gate receipts, orchestrator receipts",
                "mutability": "AUTHORITATIVE_LANE_ONLY",
            },
            {
                "zone_id": "branch_local_execution_truth",
                "boundary": "Track 03 run artifacts beneath KT_PROD_CLEANROOM/runs/post_f_track_03/**",
                "mutability": "FROZEN_EXECUTION_HISTORY__NO_PREP_LANE_MUTATION",
            },
            {
                "zone_id": "parallel_prep_scaffolds",
                "boundary": "KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_*",
                "mutability": "PREP_ONLY__NON_AUTHORITATIVE",
            },
            {
                "zone_id": "quarantine_and_history",
                "boundary": "KT-Codex/**, KT_ARCHIVE/**, previously quarantined non-live surfaces",
                "mutability": "QUARANTINE_ONLY",
            },
        ],
        "canonical_scope_manifest": {
            "scope_id": "post_f_canonical_scope_v1",
            "authoritative_branch": "main",
            "authoritative_subject_head": str(verdict_receipt.get("subject_head", "")).strip(),
            "live_truth_roots": [
                "KT_PROD_CLEANROOM/reports/cohort0_successor_*",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_01_*",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_*",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_*",
            ],
        },
        "readiness_scope_manifest": {
            "scope_id": "track03_review_readiness_scope_v1",
            "required_roots": [
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_human_review_*",
                "KT_PROD_CLEANROOM/runs/post_f_track_03/run-20260424-152430-bb49da8/artifacts/*",
                "KT_PROD_CLEANROOM/runs/post_f_track_03/run-20260424-152430-bb49da8/staging/signatures/*",
                "KT_PROD_CLEANROOM/runs/post_f_track_03/run-20260424-152430-bb49da8/staging/bundle/*",
            ],
        },
        "noncanonical_quarantine_candidate_list": {
            "policy_ref": common.resolve_path(root, "KT_PROD_CLEANROOM/reports/legacy_quarantine_receipt.json").as_posix(),
            "candidates": [
                "KT_PROD_CLEANROOM/runs/post_f_track_03/**",
                "KT-Codex/**",
                "KT_ARCHIVE/**",
                "root reports/ forensic freeze artifacts",
            ],
        },
        "promotion_safe_boundary_recommendations": [
            "Keep Track 03 run-root artifacts preserved but out of canonical live truth surfaces.",
            "Require human-review verdict plus protected merge before any stage_and_promote invocation.",
            "Treat prep-lane outputs as non-authoritative until a later authoritative court explicitly adopts them.",
        ],
        "source_refs": common.output_ref_dict(
            matrix_packet=common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_prep_lane_matrix_packet.json"),
            legacy_quarantine_receipt=common.resolve_path(root, "KT_PROD_CLEANROOM/reports/legacy_quarantine_receipt.json"),
        ),
        "next_lawful_move": str(verdict_receipt.get("next_lawful_move", "")).strip(),
    }


def _truth_engine_packet(*, root: Path, verdict_receipt: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_post_f_parallel_truth_engine_scope_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "lane_id": "truth_engine_contradiction_validator_scaffold",
        "lane_status": "AUTHORIZED__NON_AUTHORITATIVE_PREP_ONLY",
        "claim_boundary": "Prep-only truth-engine contract. It does not rewrite live headers or mutate current posture.",
        "posture_enum": [
            "CANONICAL_MAIN_LIVE_TRUTH",
            "AUTHORITATIVE_BRANCH_NON_CANONICAL",
            "TRACK03_EXECUTION_COMPLETE__PROMOTION_GATED",
            "TRACK03_HUMAN_REVIEW_PENDING_OR_COMPLETE",
            "PARALLEL_PREP_ONLY__NON_AUTHORITATIVE",
        ],
        "truth_engine_contract": {
            "subject_head": str(verdict_receipt.get("subject_head", "")).strip(),
            "live_posture_must_be_receipt_derived": True,
            "historical_surfaces_may_explain_but_not_override": True,
            "prep_surfaces_may_not_publish_live_posture": True,
        },
        "contradiction_rules": [
            "If branch-local prep output contradicts Track 01/02/03 frozen receipts, prep output loses automatically.",
            "If a source claims canonical status from expansion/* before merge, fail closed.",
            "If stale or untracked surfaces outrank the frozen header stack, fail closed.",
        ],
        "source_precedence_table": [
            "main protected-branch canonical surfaces after merge",
            "frozen authoritative branch Track 03 review / verdict surfaces before merge",
            "frozen Track 02 and Track 01 summary receipts",
            "historical and quarantine surfaces for lineage only",
            "parallel prep scaffolds last and non-authoritative only",
        ],
        "stale_surface_exclusion_logic": {
            "exclude_untracked_authority": True,
            "exclude_historical_override": True,
            "exclude_prep_lane_posture_override": True,
            "reference_contract": common.resolve_path(root, "KT_PROD_CLEANROOM/reports/reporting_integrity_contract.json").as_posix(),
        },
        "source_refs": common.output_ref_dict(
            reporting_integrity_contract=common.resolve_path(root, "KT_PROD_CLEANROOM/reports/reporting_integrity_contract.json"),
            track02_final_summary=common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_final_summary_packet.json"),
            track03_final_summary=common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_final_summary_packet.json"),
            track03_human_review=common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_human_review_packet.json"),
        ),
        "next_lawful_move": str(verdict_receipt.get("next_lawful_move", "")).strip(),
    }


def _proof_law_packet(*, root: Path, human_review_packet: Dict[str, Any], verdict_receipt: Dict[str, Any]) -> Dict[str, Any]:
    review_bundle = dict(human_review_packet.get("review_evidence_bundle", {}))
    return {
        "schema_id": "kt.operator.cohort0_post_f_parallel_residual_proof_law_hardening_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "lane_id": "residual_proof_law_hardening_scaffold",
        "lane_status": "AUTHORIZED__NON_AUTHORITATIVE_PREP_ONLY",
        "claim_boundary": "Prep-only proof-law hardening scaffold. It does not rerun counted execution or alter Track 03 receipts.",
        "deterministic_digest_law": {
            "hash_algorithm": "sha256",
            "ordering_rule": "lexicographic file ordering",
            "tarball_rule": "sorted names, fixed mtime, owner=0, group=0, numeric-owner",
            "seed_default": 42,
            "timestamps": "RFC3339 UTC Z",
        },
        "mock_prod_admissibility_split": {
            "default_runtime": "mock_only",
            "mock_allowed_for_track03": True,
            "production_requires_explicit_env": True,
            "production_requires_operator_decision": True,
        },
        "receipt_signing_timestamp_sequence": [
            "refresh current-head receipt",
            "run smoke path",
            "run exactly one counted path for frozen manifest",
            "freeze proof bundle",
            "emit signature surface",
            "emit promotion block or promotion receipt",
        ],
        "authority_dependency_map": {
            "track03_depends_on": [
                "Track 02 final summary packet",
                "Track 03 final summary packet",
                "Track 03 human review packet",
            ],
            "execution_artifacts": [
                review_bundle.get("current_head_receipt_ref", ""),
                review_bundle.get("counted_path_receipt_ref", ""),
                review_bundle.get("proof_bundle_ref", ""),
                review_bundle.get("proof_signature_ref", ""),
            ],
        },
        "bundle_canonicalization_rules": [
            "Never back-edit counted bundle bytes after receipt freeze.",
            "Treat run-root artifacts as preserved execution truth, not canonical live posture.",
            "If a manifest row is stale, quarantine it and supersede explicitly instead of overwriting silently.",
        ],
        "source_refs": common.output_ref_dict(
            track03_final_summary=common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_final_summary_packet.json"),
            track03_human_review=common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_human_review_packet.json"),
            track03_validation_matrix=common.resolve_path(
                root, "KT_PROD_CLEANROOM/runs/post_f_track_03/run-20260424-152430-bb49da8/artifacts/validation_matrix.json"
            ),
        ),
        "next_lawful_move": str(verdict_receipt.get("next_lawful_move", "")).strip(),
    }


def _upper_stack_packet(*, root: Path, verdict_receipt: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_post_f_parallel_upper_stack_ratification_scope_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "lane_id": "upper_stack_ratification_scaffold",
        "lane_status": "AUTHORIZED__NON_AUTHORITATIVE_PREP_ONLY",
        "claim_boundary": "Prep-only upper-stack ratification scaffold. It does not claim ratification has already occurred.",
        "crucible_registry_scaffold": {
            "registry_goal": "Map bounded crucible-ready ratification objects without promoting them.",
            "source_ref": common.resolve_path(root, "KT_PROD_CLEANROOM/reports/kt_unified_convergence_contradiction_table.json").as_posix(),
        },
        "pressure_taxonomy_scaffold": {
            "pressure_classes": ["governance", "runtime", "promotion", "externality", "commercialization"],
            "goal": "Bind where future upper-stack courts apply pressure without mixing claims.",
        },
        "adapter_lifecycle_scaffold": {
            "source_ref": common.resolve_path(root, adapter_validate.DEFAULT_ADAPTER_LIFECYCLE_REL).as_posix(),
            "allowed_follow_on_steps": sorted(adapter_validate.EXPECTED_ALLOWED_FOLLOW_ON_STEPS),
        },
        "tournament_promotion_law_scaffold": {
            "next_step_anchor": adapter_validate.EXPECTED_NEXT_STEP_ID,
            "promotion_rule": "Promotion law stays blocked until adapter lifecycle and current branch law allow ordered next-step ratification.",
        },
        "router_lobe_ratification_order_scaffold": [
            adapter_validate.EXPECTED_NEXT_STEP_ID,
            "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFICATION",
            "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF",
            "B04_R6_LEARNED_ROUTER_AUTHORIZATION",
            "B04_R7_LOBE_ARCHITECTURE_RATIFICATION",
        ],
        "source_refs": common.output_ref_dict(
            contradiction_table=common.resolve_path(root, "KT_PROD_CLEANROOM/reports/kt_unified_convergence_contradiction_table.json"),
            adapter_lifecycle_contract=common.resolve_path(root, adapter_validate.DEFAULT_ADAPTER_LIFECYCLE_REL),
        ),
        "next_lawful_move": str(verdict_receipt.get("next_lawful_move", "")).strip(),
    }


def run(*, reports_root: Path, matrix_packet_path: Path, human_review_packet_path: Path, verdict_receipt_path: Path) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_WORKING_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: parallel prep scaffolds must run on {REQUIRED_WORKING_BRANCH}, got {branch_name}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: parallel prep scaffolds require a clean worktree before execution")

    matrix_packet = common.load_json_required(root, matrix_packet_path, label="parallel prep lane matrix packet")
    human_review_packet = common.load_json_required(root, human_review_packet_path, label="Track 03 human review packet")
    verdict_receipt = common.load_json_required(root, verdict_receipt_path, label="Track 03 human review verdict receipt")
    common.ensure_pass(matrix_packet, label="parallel prep lane matrix packet")
    common.ensure_pass(human_review_packet, label="Track 03 human review packet")
    common.ensure_pass(verdict_receipt, label="Track 03 human review verdict receipt")
    authoritative_next_move = str(verdict_receipt.get("next_lawful_move", "")).strip()
    if not authoritative_next_move:
        raise RuntimeError("FAIL_CLOSED: prep scaffolds require a concrete authoritative next move from the human review verdict")

    trust_zone_packet = _trust_zone_packet(root=root, matrix_packet=matrix_packet, verdict_receipt=verdict_receipt)
    truth_engine_packet = _truth_engine_packet(root=root, verdict_receipt=verdict_receipt)
    proof_law_packet = _proof_law_packet(root=root, human_review_packet=human_review_packet, verdict_receipt=verdict_receipt)
    upper_stack_packet = _upper_stack_packet(root=root, verdict_receipt=verdict_receipt)

    write_json_stable((reports_root / OUTPUT_TRUST_ZONE_PACKET).resolve(), trust_zone_packet)
    write_json_stable((reports_root / OUTPUT_TRUTH_ENGINE_PACKET).resolve(), truth_engine_packet)
    write_json_stable((reports_root / OUTPUT_PROOF_LAW_PACKET).resolve(), proof_law_packet)
    write_json_stable((reports_root / OUTPUT_UPPER_STACK_PACKET).resolve(), upper_stack_packet)
    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_parallel_prep_scaffold_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "outcome": OUTCOME,
        "working_branch": branch_name,
        "working_branch_head_at_scaffold_time": _current_head(root),
        "working_branch_non_authoritative_until_protected_merge": True,
        "lane_packet_count": 4,
        "subject_head": str(verdict_receipt.get("subject_head", "")).strip(),
        "next_lawful_move": authoritative_next_move,
    }
    write_json_stable((reports_root / OUTPUT_RECEIPT).resolve(), receipt)
    common.write_text(
        (reports_root / OUTPUT_REPORT).resolve(),
        common.report_lines(
            "Cohort0 Post-F Parallel Prep Scaffold Report",
            [
                f"- Execution status: `{EXECUTION_STATUS}`",
                f"- Outcome: `{OUTCOME}`",
                "- Lane packets emitted: `4`",
                f"- Authoritative next move preserved: `{authoritative_next_move}`",
            ],
        ),
    )
    return {
        "outcome": OUTCOME,
        "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(),
        "next_lawful_move": authoritative_next_move,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Emit the first parallel prep scaffold packets.")
    parser.add_argument(
        "--matrix-packet",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_prep_lane_matrix_packet.json",
    )
    parser.add_argument(
        "--human-review-packet",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_human_review_packet.json",
    )
    parser.add_argument(
        "--human-review-verdict-receipt",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_human_review_verdict_receipt.json",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        matrix_packet_path=common.resolve_path(root, args.matrix_packet),
        human_review_packet_path=common.resolve_path(root, args.human_review_packet),
        verdict_receipt_path=common.resolve_path(root, args.human_review_verdict_receipt),
    )
    print(result["outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
