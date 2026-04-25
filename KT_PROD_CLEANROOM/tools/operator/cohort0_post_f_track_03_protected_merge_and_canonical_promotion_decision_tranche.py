from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_post_f_track_03_protected_merge_and_canonical_promotion_decision_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_track_03_protected_merge_and_canonical_promotion_decision_receipt.json"
OUTPUT_BLOCKERS = "cohort0_post_f_track_03_protected_merge_and_canonical_promotion_blocker_ledger.json"
OUTPUT_REPORT = "COHORT0_POST_F_TRACK_03_PROTECTED_MERGE_AND_CANONICAL_PROMOTION_DECISION_REPORT.md"

REQUIRED_WORKING_BRANCH = "expansion/post-f-track-01"
EXECUTION_STATUS = "PASS__TRACK_03_PROTECTED_MERGE_AND_CANONICAL_PROMOTION_DECISION_BOUND"
OUTCOME_MERGE_DEFERRED = "MERGE_DEFERRED__NAMED_BLOCKERS_ONLY"
OUTCOME_MERGE_APPROVED_DEFERRED = "MERGE_APPROVED__PACKAGE_PROMOTION_DEFERRED"
OUTCOME_MERGE_APPROVED_PARTIAL = "MERGE_APPROVED__PACKAGE_PROMOTION_PARTIALLY_AUTHORIZED"
NEXT_MOVE_MERGE_DEFERRED = "AUTHOR_POST_F_TRACK_03_MERGE_BLOCKER_REMEDIATION_PACKET"
NEXT_MOVE_MERGE_APPROVED_DEFERRED = "EXECUTE_PROTECTED_MERGE_TO_MAIN__PACKAGE_PROMOTION_STILL_DEFERRED"
NEXT_MOVE_MERGE_APPROVED_PARTIAL = "EXECUTE_PROTECTED_MERGE_TO_MAIN__PACKAGE_PROMOTION_PARTIAL_AUTHORIZATION_HELD"


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


def _git_diff_name_only(root: Path, left: str, right: str) -> List[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{left}...{right}"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def build_outputs(
    *,
    branch_name: str,
    branch_head: str,
    main_head: str,
    merge_base: str,
    changed_paths: List[str],
    merge_prep_packet: Dict[str, Any],
    merge_prep_receipt: Dict[str, Any],
    review_verdict_receipt: Dict[str, Any],
) -> Dict[str, Dict[str, Any] | str]:
    authority_header = dict(merge_prep_packet.get("authority_header", {}))
    artifact_split = dict(merge_prep_packet.get("exact_promoted_artifact_set", {}))
    merge_gate_matrix = dict(merge_prep_packet.get("merge_gate_matrix", {}))
    post_merge_fork = dict(merge_prep_packet.get("post_merge_authoritative_fork", {}))

    merge_blockers: List[Dict[str, str]] = []
    if branch_name != REQUIRED_WORKING_BRANCH:
        merge_blockers.append(
            {
                "blocker_id": "WRONG_WORKING_BRANCH",
                "summary": f"Decision court expected {REQUIRED_WORKING_BRANCH}, got {branch_name}.",
            }
        )
    if merge_base != main_head:
        merge_blockers.append(
            {
                "blocker_id": "MAIN_NOT_CURRENT_MERGE_BASE",
                "summary": "main has diverged from the branch merge base; refresh/reconcile before protected merge decision.",
            }
        )
    if not changed_paths:
        merge_blockers.append(
            {
                "blocker_id": "NO_BRANCH_DELTA_TO_MERGE",
                "summary": "Branch has no delta relative to main, so protected merge would be a no-op.",
            }
        )
    if str(review_verdict_receipt.get("review_outcome", "")).strip() not in {"APPROVE_AS_IS", "APPROVE_WITH_NAMED_NON_STRUCTURAL_EDITS"}:
        merge_blockers.append(
            {
                "blocker_id": "REVIEW_NOT_APPROVED",
                "summary": "Human review verdict is not in an approved state.",
            }
        )

    package_auto_rows = list(artifact_split.get("package_internal_auto_promotion_set", []))
    package_skipped_rows = list(artifact_split.get("package_internal_review_approved_but_auto_skipped", []))
    package_outside_scope = list(artifact_split.get("review_approved_but_outside_current_stage_and_promote_scope", []))
    package_deferred_reasons: List[Dict[str, str]] = []
    if package_skipped_rows:
        package_deferred_reasons.append(
            {
                "reason_id": "HUMAN_REVIEW_REQUIRED_FILES_STAY_PACKAGE_GATED",
                "summary": f"{len(package_skipped_rows)} reviewed files remain intentionally outside package auto-promotion because they still carry human_review_required headers.",
            }
        )
    if package_outside_scope:
        package_deferred_reasons.append(
            {
                "reason_id": "REVIEWED_FILES_OUTSIDE_STAGE_AND_PROMOTE_SCOPE",
                "summary": f"{len(package_outside_scope)} reviewed files remain outside the current stage_and_promote.sh selected directories.",
            }
        )
    if not bool(merge_prep_packet.get("exact_post_merge_truth_update", {}).get("package_promotion_still_requires_explicit_step", False)):
        package_deferred_reasons.append(
            {
                "reason_id": "PACKAGE_PROMOTION_EXPLICIT_STEP_NOT_PRESERVED",
                "summary": "Merge prep packet no longer preserves package promotion as a separate explicit step.",
            }
        )

    if merge_blockers:
        outcome = OUTCOME_MERGE_DEFERRED
        next_move = NEXT_MOVE_MERGE_DEFERRED
    elif package_deferred_reasons:
        outcome = OUTCOME_MERGE_APPROVED_DEFERRED
        next_move = NEXT_MOVE_MERGE_APPROVED_DEFERRED
    else:
        outcome = OUTCOME_MERGE_APPROVED_PARTIAL
        next_move = NEXT_MOVE_MERGE_APPROVED_PARTIAL

    blocker_ledger = {
        "schema_id": "kt.operator.cohort0_post_f_track_03_protected_merge_and_canonical_promotion_blocker_ledger.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "decision_outcome": outcome,
        "merge_blockers": merge_blockers,
        "package_promotion_deferred_reasons": package_deferred_reasons,
    }
    packet = {
        "schema_id": "kt.operator.cohort0_post_f_track_03_protected_merge_and_canonical_promotion_decision_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "decision_outcome": outcome,
        "claim_boundary": (
            "This court decides only whether protected merge to main is approved and whether package promotion remains deferred or partially authorized. "
            "It does not execute the merge or package promotion."
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
        "merge_eligibility_snapshot": {
            "working_branch": branch_name,
            "working_branch_head": branch_head,
            "main_head": main_head,
            "merge_base_with_main": merge_base,
            "main_is_current_merge_base": merge_base == main_head,
            "changed_path_count_vs_main": len(changed_paths),
            "sample_changed_paths": changed_paths[:25],
            "clean_branch_required_now": bool(merge_gate_matrix.get("clean_branch_required_now", False)),
        },
        "artifact_split_frozen": artifact_split,
        "package_promotion_lane_state": {
            "auto_promotion_candidate_count": len(package_auto_rows),
            "review_approved_auto_skip_count": len(package_skipped_rows),
            "review_approved_out_of_scope_count": len(package_outside_scope),
            "package_promotion_boundary": str(
                merge_prep_packet.get("exact_post_merge_truth_update", {}).get("package_promotion_boundary", "")
            ).strip(),
        },
        "decision_reasoning": {
            "merge_gate_matrix": merge_gate_matrix,
            "review_outcome": str(review_verdict_receipt.get("review_outcome", "")).strip(),
            "merge_blocker_count": len(merge_blockers),
            "package_promotion_deferred_reason_count": len(package_deferred_reasons),
        },
        "post_merge_authoritative_fork": post_merge_fork,
        "blocker_ledger_ref": common.resolve_path(
            repo_root(), "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_protected_merge_and_canonical_promotion_blocker_ledger.json"
        ).as_posix(),
        "subject_head": str(review_verdict_receipt.get("subject_head", "")).strip(),
        "next_lawful_move": next_move,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_track_03_protected_merge_and_canonical_promotion_decision_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "decision_outcome": outcome,
        "merge_blocker_count": len(merge_blockers),
        "package_promotion_deferred_reason_count": len(package_deferred_reasons),
        "subject_head": str(review_verdict_receipt.get("subject_head", "")).strip(),
        "next_lawful_move": next_move,
    }
    report = common.report_lines(
        "Cohort0 Post-F Track 03 Protected Merge And Canonical Promotion Decision Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Decision outcome: `{outcome}`",
            f"- Working branch head: `{branch_head}`",
            f"- Main head: `{main_head}`",
            f"- Main is merge base: `{merge_base == main_head}`",
            f"- Changed path count vs main: `{len(changed_paths)}`",
            f"- Merge blocker count: `{len(merge_blockers)}`",
            f"- Package promotion deferred reason count: `{len(package_deferred_reasons)}`",
            f"- Next lawful move: `{next_move}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "blockers": blocker_ledger, "report": report}


def run(
    *,
    reports_root: Path,
    merge_prep_packet_path: Path,
    merge_prep_receipt_path: Path,
    review_verdict_receipt_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_WORKING_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: protected merge decision must run on {REQUIRED_WORKING_BRANCH}, got {branch_name}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: protected merge decision requires a clean worktree before execution")

    merge_prep_packet = common.load_json_required(root, merge_prep_packet_path, label="Track 03 merge and promotion prep packet")
    merge_prep_receipt = common.load_json_required(root, merge_prep_receipt_path, label="Track 03 merge and promotion prep receipt")
    review_verdict_receipt = common.load_json_required(root, review_verdict_receipt_path, label="Track 03 human review verdict receipt")
    common.ensure_pass(merge_prep_packet, label="Track 03 merge and promotion prep packet")
    common.ensure_pass(merge_prep_receipt, label="Track 03 merge and promotion prep receipt")
    common.ensure_pass(review_verdict_receipt, label="Track 03 human review verdict receipt")

    if str(merge_prep_receipt.get("next_lawful_move", "")).strip() != "CONVENE_POST_F_TRACK_03_PROTECTED_MERGE_AND_CANONICAL_PROMOTION_DECISION":
        raise RuntimeError("FAIL_CLOSED: merge prep packet does not authorize the protected merge decision court")

    main_head = _git_rev_parse(root, "main")
    branch_head = _git_rev_parse(root, "HEAD")
    merge_base = _git_merge_base(root, "main", "HEAD")
    changed_paths = _git_diff_name_only(root, "main", "HEAD")

    outputs = build_outputs(
        branch_name=branch_name,
        branch_head=branch_head,
        main_head=main_head,
        merge_base=merge_base,
        changed_paths=changed_paths,
        merge_prep_packet=merge_prep_packet,
        merge_prep_receipt=merge_prep_receipt,
        review_verdict_receipt=review_verdict_receipt,
    )

    common.write_outputs(
        packet_path=(reports_root / OUTPUT_PACKET).resolve(),
        receipt_path=(reports_root / OUTPUT_RECEIPT).resolve(),
        report_path=(reports_root / OUTPUT_REPORT).resolve(),
        packet=outputs["packet"],
        receipt=outputs["receipt"],
        report_text=str(outputs["report"]),
    )
    common.write_text(
        (reports_root / OUTPUT_BLOCKERS).resolve(),
        __import__("json").dumps(outputs["blockers"], indent=2, sort_keys=True) + "\n",
    )
    return {
        "decision_outcome": str(outputs["receipt"]["decision_outcome"]),
        "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(),
        "next_lawful_move": str(outputs["receipt"]["next_lawful_move"]),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Convene the Track 03 protected merge and canonical promotion decision court.")
    parser.add_argument(
        "--merge-prep-packet",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_merge_and_promotion_prep_packet.json",
    )
    parser.add_argument(
        "--merge-prep-receipt",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_merge_and_promotion_prep_receipt.json",
    )
    parser.add_argument(
        "--review-verdict-receipt",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_human_review_verdict_receipt.json",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        merge_prep_packet_path=common.resolve_path(root, args.merge_prep_packet),
        merge_prep_receipt_path=common.resolve_path(root, args.merge_prep_receipt),
        review_verdict_receipt_path=common.resolve_path(root, args.review_verdict_receipt),
    )
    print(result["decision_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
