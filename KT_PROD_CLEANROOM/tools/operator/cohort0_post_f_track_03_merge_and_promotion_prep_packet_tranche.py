from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_post_f_track_03_merge_and_promotion_prep_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_track_03_merge_and_promotion_prep_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_TRACK_03_MERGE_AND_PROMOTION_PREP_REPORT.md"

REQUIRED_WORKING_BRANCH = "expansion/post-f-track-01"
DEFAULT_RUN_ID = "run-20260424-152430-bb49da8"
EXECUTION_STATUS = "PASS__TRACK_03_MERGE_AND_PROMOTION_PREP_PACKET_BOUND"
PREP_OUTCOME = "TRACK_03_MERGE_AND_PROMOTION_PREP_BOUND__REVIEW_CLEARED_CANDIDATE"
NEXT_MOVE = "CONVENE_POST_F_TRACK_03_PROTECTED_MERGE_AND_CANONICAL_PROMOTION_DECISION"

STAGE_AND_PROMOTE_SELECTED_DIRS = ["reports", "governance", "packet", "runtime", "docs"]
POST_MERGE_LANE_RANKING = [
    {
        "rank": 1,
        "lane_id": "truth_engine_contradiction_validator_scaffold",
        "promotion_rationale": "Highest leverage for preventing future posture drift and stale-surface misgrading.",
    },
    {
        "rank": 2,
        "lane_id": "trust_zone_boundary_purification_scaffold",
        "promotion_rationale": "Next highest leverage for boundary hardening and canonical/noncanonical separation.",
    },
    {
        "rank": 3,
        "lane_id": "residual_proof_law_hardening_scaffold",
        "promotion_rationale": "Hardens future proof courts after truth and boundary surfaces are locked down.",
    },
    {
        "rank": 4,
        "lane_id": "upper_stack_ratification_scaffold",
        "promotion_rationale": "Largest expansion surface; should stand on the first three lanes first.",
    },
]


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


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _scan_stage_and_promote_sets(staging_root: Path, script_path: Path) -> Dict[str, List[Dict[str, str]]]:
    script_text = _read_text(script_path)
    expected_literal = 'selected = ["reports", "governance", "packet", "runtime", "docs"]'
    if expected_literal not in script_text:
        raise RuntimeError("FAIL_CLOSED: stage_and_promote.sh selected directory set drifted from the reviewed Track 03 law")

    auto_promoted: List[Dict[str, str]] = []
    skipped_human_review_required: List[Dict[str, str]] = []
    for rel in STAGE_AND_PROMOTE_SELECTED_DIRS:
        src = staging_root / rel
        if not src.exists():
            continue
        for path in sorted(p for p in src.rglob("*") if p.is_file()):
            rel_path = path.relative_to(staging_root).as_posix()
            header = _read_text(path).splitlines()[:10]
            row = {"path": rel_path, "sha256": _sha256(path)}
            if any("human_review_required: true" in line for line in header):
                skipped_human_review_required.append(row)
            else:
                auto_promoted.append(row)
    return {
        "auto_promoted": auto_promoted,
        "skipped_human_review_required": skipped_human_review_required,
    }


def _reviewed_outside_auto_scope(reviewed_files: List[str]) -> List[str]:
    selected_prefixes = tuple(f"{item}/" for item in STAGE_AND_PROMOTE_SELECTED_DIRS)
    return [path for path in reviewed_files if not path.startswith(selected_prefixes)]


def build_outputs(
    *,
    root: Path,
    branch_name: str,
    branch_head: str,
    review_verdict_packet: Dict[str, Any],
    review_verdict_receipt: Dict[str, Any],
    promotion_recommendation: Dict[str, Any],
    final_summary_packet: Dict[str, Any],
    prep_scaffold_receipt: Dict[str, Any],
    staging_root: Path,
    stage_and_promote_script_path: Path,
) -> Dict[str, Dict[str, Any] | str]:
    authority_header = dict(review_verdict_packet.get("authority_header", {}))
    promotion_sets = _scan_stage_and_promote_sets(staging_root, stage_and_promote_script_path)
    reviewed_files = list(review_verdict_packet.get("review_scope", {}).get("reviewed_files", []))
    reviewed_outside_scope = _reviewed_outside_auto_scope(reviewed_files)

    packet = {
        "schema_id": "kt.operator.cohort0_post_f_track_03_merge_and_promotion_prep_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "prep_outcome": PREP_OUTCOME,
        "claim_boundary": (
            "This packet freezes merge and promotion preparation only. It does not merge the branch, does not execute stage_and_promote.sh, "
            "and does not widen Track 03, Track 01, Track 02, Gate F, or broader KT claims."
        ),
        "authority_header": {
            "canonical_authority_branch": "main",
            "working_branch": branch_name,
            "working_branch_non_authoritative_until_protected_merge": True,
            "gate_d_cleared_on_successor_line": bool(authority_header.get("gate_d_cleared_on_successor_line", False)),
            "gate_e_open_on_successor_line": bool(authority_header.get("gate_e_open_on_successor_line", False)),
            "gate_f_narrow_wedge_confirmed": bool(authority_header.get("gate_f_narrow_wedge_confirmed", False)),
            "gate_f_open": bool(authority_header.get("gate_f_open", False)),
            "post_f_reaudit_passed": bool(authority_header.get("post_f_reaudit_passed", False)),
        },
        "promotion_target_and_authority_rule": {
            "eligible_source_branch": branch_name,
            "eligible_target_branch": "main",
            "repo_merge_channel": "protected_merge_only__no_direct_push",
            "merge_mode_recommendation": "non_fast_forward_or_pr_merge_for_legible history",
            "package_internal_promotion_entrypoint": stage_and_promote_script_path.resolve().as_posix(),
            "authority_rule": (
                "Protected merge to main is the only action that changes canonical repo authority. "
                "Package-internal canonical/ promotion remains a separate explicit operator decision after merge."
            ),
        },
        "exact_promoted_artifact_set": {
            "repo_merge_authoritative_truth_surfaces": [
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_final_summary_packet.json",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_final_summary_receipt.json",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_human_review_packet.json",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_human_review_receipt.json",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_human_review_verdict_packet.json",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_human_review_verdict_receipt.json",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_human_review_matrix.json",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_human_review_blocker_ledger.json",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_promotion_recommendation.json",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_merge_and_promotion_prep_packet.json",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_merge_and_promotion_prep_receipt.json",
            ],
            "repo_merge_support_but_non_authoritative_surfaces": [
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_prep_lane_matrix_packet.json",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_prep_lane_matrix_receipt.json",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_trust_zone_boundary_scope_packet.json",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_truth_engine_scope_packet.json",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_residual_proof_law_hardening_packet.json",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_upper_stack_ratification_scope_packet.json",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_prep_scaffold_receipt.json",
            ],
            "package_internal_auto_promotion_set": promotion_sets["auto_promoted"],
            "package_internal_review_approved_but_auto_skipped": promotion_sets["skipped_human_review_required"],
            "review_approved_but_outside_current_stage_and_promote_scope": reviewed_outside_scope,
            "historical_or_branch_local_execution_record": [
                "KT_PROD_CLEANROOM/runs/post_f_track_03/run-20260424-152430-bb49da8/artifacts/**",
                "KT_PROD_CLEANROOM/runs/post_f_track_03/run-20260424-152430-bb49da8/staging/bundle/**",
                "KT_PROD_CLEANROOM/runs/post_f_track_03/run-20260424-152430-bb49da8/staging/signatures/**",
                "KT_PROD_CLEANROOM/runs/post_f_track_03/run-20260424-152430-bb49da8/staging/work/**",
            ],
        },
        "merge_gate_matrix": {
            "clean_branch_required_now": True,
            "review_verdict_required": str(review_verdict_receipt.get("review_outcome", "")).strip(),
            "review_verdict_must_be_pass": str(review_verdict_receipt.get("status", "")).strip() == "PASS",
            "multisig_threshold_satisfied": bool(final_summary_packet.get("promotion_boundary", {}).get("multisig_threshold_satisfied", False)),
            "no_silent_overwrite_rule": True,
            "authoritative_branch_constraint": "promotion may not run from expansion/* branch",
            "required_checks": [
                "Track 03 final summary receipt PASS",
                "Track 03 human review verdict PASS",
                "promotion recommendation PASS and merge_allowed_after_review=true",
                "protected merge to main",
                "clean tracked state on canonical branch before any stage_and_promote invocation",
                "stage_and_promote.sh --check-multisig-only passes on canonical line",
            ],
        },
        "exact_post_merge_truth_update": {
            "changes_on_merge": [
                "Track 03 becomes canonical repo-resident reviewed truth instead of branch-only reviewed truth.",
                "working_branch_non_authoritative_until_protected_merge becomes false only on merged main-level surfaces.",
            ],
            "does_not_change_on_merge": [
                "Gate F remains one narrow wedge confirmed in local_verifier_mode only.",
                "Track 01 remains bounded comparative proof only.",
                "Track 02 remains bounded dual-audit truth, not broad frontier proof.",
                "Track 03 remains a bounded H1 proof-path result, not broad system ratification.",
            ],
            "package_promotion_still_requires_explicit_step": True,
            "package_promotion_boundary": str(promotion_recommendation.get("canonical_promotion_boundary", "")).strip(),
        },
        "post_merge_authoritative_fork": {
            "ranked_prep_lane_promotions": POST_MERGE_LANE_RANKING,
            "first_lane_to_promote": POST_MERGE_LANE_RANKING[0]["lane_id"],
            "first_lane_rationale": POST_MERGE_LANE_RANKING[0]["promotion_rationale"],
        },
        "supporting_receipts": {
            "review_outcome": str(review_verdict_receipt.get("review_outcome", "")).strip(),
            "promotion_recommendation": str(promotion_recommendation.get("promotion_recommendation", "")).strip(),
            "prep_scaffold_outcome": str(prep_scaffold_receipt.get("outcome", "")).strip(),
        },
        "subject_head": str(review_verdict_receipt.get("subject_head", "")).strip(),
        "next_lawful_move": NEXT_MOVE,
    }

    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_track_03_merge_and_promotion_prep_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "prep_outcome": PREP_OUTCOME,
        "package_internal_auto_promotion_file_count": len(promotion_sets["auto_promoted"]),
        "package_internal_review_auto_skip_count": len(promotion_sets["skipped_human_review_required"]),
        "review_outcome": str(review_verdict_receipt.get("review_outcome", "")).strip(),
        "recommended_post_merge_first_lane": POST_MERGE_LANE_RANKING[0]["lane_id"],
        "subject_head": str(review_verdict_receipt.get("subject_head", "")).strip(),
        "next_lawful_move": NEXT_MOVE,
    }

    report = common.report_lines(
        "Cohort0 Post-F Track 03 Merge And Promotion Prep Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Prep outcome: `{PREP_OUTCOME}`",
            f"- Review outcome: `{review_verdict_receipt.get('review_outcome', '')}`",
            f"- Package auto-promotion file count: `{len(promotion_sets['auto_promoted'])}`",
            f"- Package review-auto-skip count: `{len(promotion_sets['skipped_human_review_required'])}`",
            f"- First post-merge lane: `{POST_MERGE_LANE_RANKING[0]['lane_id']}`",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    review_verdict_packet_path: Path,
    review_verdict_receipt_path: Path,
    promotion_recommendation_path: Path,
    final_summary_packet_path: Path,
    prep_scaffold_receipt_path: Path,
    run_root: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_WORKING_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: Track 03 merge and promotion prep must run on {REQUIRED_WORKING_BRANCH}, got {branch_name}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: Track 03 merge and promotion prep requires a clean worktree before execution")

    review_verdict_packet = common.load_json_required(root, review_verdict_packet_path, label="Track 03 human review verdict packet")
    review_verdict_receipt = common.load_json_required(root, review_verdict_receipt_path, label="Track 03 human review verdict receipt")
    promotion_recommendation = common.load_json_required(root, promotion_recommendation_path, label="Track 03 promotion recommendation")
    final_summary_packet = common.load_json_required(root, final_summary_packet_path, label="Track 03 final summary packet")
    prep_scaffold_receipt = common.load_json_required(root, prep_scaffold_receipt_path, label="parallel prep scaffold receipt")

    common.ensure_pass(review_verdict_packet, label="Track 03 human review verdict packet")
    common.ensure_pass(review_verdict_receipt, label="Track 03 human review verdict receipt")
    common.ensure_pass(promotion_recommendation, label="Track 03 promotion recommendation")
    common.ensure_pass(final_summary_packet, label="Track 03 final summary packet")
    common.ensure_pass(prep_scaffold_receipt, label="parallel prep scaffold receipt")

    if str(review_verdict_receipt.get("review_outcome", "")).strip() not in {"APPROVE_AS_IS", "APPROVE_WITH_NAMED_NON_STRUCTURAL_EDITS"}:
        raise RuntimeError("FAIL_CLOSED: merge and promotion prep requires review approval, not rejection")
    if not bool(promotion_recommendation.get("merge_allowed_after_review", False)):
        raise RuntimeError("FAIL_CLOSED: merge and promotion prep requires merge_allowed_after_review=true")
    if str(review_verdict_receipt.get("next_lawful_move", "")).strip() != "AUTHOR_POST_F_TRACK_03_MERGE_AND_PROMOTION_PREP_PACKET":
        raise RuntimeError("FAIL_CLOSED: human review verdict does not authorize merge and promotion prep as the next move")

    staging_root = common.resolve_path(root, run_root / "staging")
    stage_and_promote_script_path = staging_root / "scripts" / "stage_and_promote.sh"
    if not stage_and_promote_script_path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing stage_and_promote.sh at {stage_and_promote_script_path.as_posix()}")

    outputs = build_outputs(
        root=root,
        branch_name=branch_name,
        branch_head=_current_head(root),
        review_verdict_packet=review_verdict_packet,
        review_verdict_receipt=review_verdict_receipt,
        promotion_recommendation=promotion_recommendation,
        final_summary_packet=final_summary_packet,
        prep_scaffold_receipt=prep_scaffold_receipt,
        staging_root=staging_root,
        stage_and_promote_script_path=stage_and_promote_script_path,
    )

    common.write_outputs(
        packet_path=(reports_root / OUTPUT_PACKET).resolve(),
        receipt_path=(reports_root / OUTPUT_RECEIPT).resolve(),
        report_path=(reports_root / OUTPUT_REPORT).resolve(),
        packet=outputs["packet"],
        receipt=outputs["receipt"],
        report_text=str(outputs["report"]),
    )
    return {
        "prep_outcome": PREP_OUTCOME,
        "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(),
        "next_lawful_move": NEXT_MOVE,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Author the Track 03 merge and promotion prep packet.")
    parser.add_argument(
        "--review-verdict-packet",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_human_review_verdict_packet.json",
    )
    parser.add_argument(
        "--review-verdict-receipt",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_human_review_verdict_receipt.json",
    )
    parser.add_argument(
        "--promotion-recommendation",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_promotion_recommendation.json",
    )
    parser.add_argument(
        "--final-summary-packet",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_final_summary_packet.json",
    )
    parser.add_argument(
        "--prep-scaffold-receipt",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_prep_scaffold_receipt.json",
    )
    parser.add_argument(
        "--run-root",
        default=f"KT_PROD_CLEANROOM/runs/post_f_track_03/{DEFAULT_RUN_ID}",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        review_verdict_packet_path=common.resolve_path(root, args.review_verdict_packet),
        review_verdict_receipt_path=common.resolve_path(root, args.review_verdict_receipt),
        promotion_recommendation_path=common.resolve_path(root, args.promotion_recommendation),
        final_summary_packet_path=common.resolve_path(root, args.final_summary_packet),
        prep_scaffold_receipt_path=common.resolve_path(root, args.prep_scaffold_receipt),
        run_root=common.resolve_path(root, args.run_root),
    )
    print(result["prep_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
