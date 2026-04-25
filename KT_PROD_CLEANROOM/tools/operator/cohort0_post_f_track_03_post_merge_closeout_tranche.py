from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_SNAPSHOT = "cohort0_post_f_track_03_post_merge_branch_snapshot.json"
OUTPUT_RECEIPT = "cohort0_post_f_track_03_post_merge_closeout_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_TRACK_03_POST_MERGE_CLOSEOUT_REPORT.md"

REQUIRED_BRANCH = "main"
SOURCE_BRANCH = "expansion/post-f-track-01"
EXECUTION_STATUS = "PASS__TRACK_03_PROTECTED_MERGE_EXECUTED__PACKAGE_PROMOTION_DEFERRED"
POST_MERGE_STATUS = "PASS__TRACK_03_CANONICAL_REPO_AUTHORITY_MERGED_TO_MAIN"
NEXT_MOVE = "AUTHOR_POST_F_TRUTH_ENGINE_CONTRADICTION_VALIDATOR_AUTHORITY_PACKET"


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


def _git_commit_parents(root: Path, ref: str) -> List[str]:
    result = subprocess.run(
        ["git", "rev-list", "--parents", "-n", "1", ref],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    rows = [part.strip() for part in result.stdout.strip().split() if part.strip()]
    if len(rows) < 3:
        raise RuntimeError(f"FAIL_CLOSED: commit {ref} must be a merge commit for Track 03 closeout anchoring")
    return rows


def _git_message(root: Path, ref: str) -> str:
    result = subprocess.run(
        ["git", "log", "-1", "--pretty=%B", ref],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout.strip()


def _latest_first_parent_merge_commit(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-list", "--first-parent", "--merges", "-n", "1", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    merge_commit = result.stdout.strip()
    if not merge_commit:
        raise RuntimeError("FAIL_CLOSED: no first-parent merge commit found on current main history for Track 03 closeout")
    return merge_commit


def build_outputs(
    *,
    current_head: str,
    merge_commit: str,
    head_commit: str,
    pre_merge_main_tip: str,
    merged_source_tip: str,
    merge_message: str,
    decision_packet: Dict[str, Any],
    decision_receipt: Dict[str, Any],
) -> Dict[str, Dict[str, Any] | str]:
    authority_header = dict(decision_packet.get("authority_header", {}))
    post_merge_fork = dict(decision_packet.get("post_merge_authoritative_fork", {}))
    artifact_split = dict(decision_packet.get("artifact_split_frozen", {}))
    package_state = dict(decision_packet.get("package_promotion_lane_state", {}))

    snapshot = {
        "snapshot_type": "POST_F_TRACK_03_POST_MERGE_CANONICAL_BRANCH_SNAPSHOT",
        "branch": REQUIRED_BRANCH,
        "head_commit": current_head,
        "merge_commit": merge_commit,
        "merge_message": merge_message,
        "source_branch": SOURCE_BRANCH,
        "source_tip": merged_source_tip,
        "pre_merge_main_tip": pre_merge_main_tip,
        "track03_repo_authority_now_canonical": True,
        "package_promotion_still_deferred": True,
        "decision_outcome": str(decision_receipt.get("decision_outcome", "")).strip(),
        "theorem_posture": {
            "gate_d_cleared_on_successor_line": bool(authority_header.get("gate_d_cleared_on_successor_line", False)),
            "gate_e_open_on_successor_line": bool(authority_header.get("gate_e_open_on_successor_line", False)),
        },
        "product_posture": {
            "gate_f_narrow_wedge_confirmed": bool(authority_header.get("gate_f_narrow_wedge_confirmed", False)),
            "gate_f_open": bool(authority_header.get("gate_f_open", False)),
            "post_f_reaudit_passed": bool(authority_header.get("post_f_reaudit_passed", False)),
        },
        "package_promotion_split": {
            "auto_promotion_candidate_count": int(package_state.get("auto_promotion_candidate_count", 0)),
            "review_approved_auto_skip_count": int(package_state.get("review_approved_auto_skip_count", 0)),
            "review_approved_out_of_scope_count": int(package_state.get("review_approved_out_of_scope_count", 0)),
            "package_promotion_boundary": str(package_state.get("package_promotion_boundary", "")).strip(),
        },
        "first_post_merge_authoritative_lane": str(post_merge_fork.get("first_lane_to_promote", "")).strip(),
        "retained_non_authoritative_prep_lanes": [
            row.get("lane_id", "")
            for row in post_merge_fork.get("ranked_prep_lane_promotions", [])
            if isinstance(row, dict) and str(row.get("lane_id", "")).strip() and str(row.get("lane_id", "")).strip() != str(post_merge_fork.get("first_lane_to_promote", "")).strip()
        ],
        "artifact_split_summary": {
            "repo_merge_authoritative_truth_surface_count": len(artifact_split.get("repo_merge_authoritative_truth_surfaces", [])),
            "repo_merge_support_surface_count": len(artifact_split.get("repo_merge_support_but_non_authoritative_surfaces", [])),
        },
    }

    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_track_03_post_merge_closeout_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "post_merge_status": POST_MERGE_STATUS,
        "target_branch": REQUIRED_BRANCH,
        "merged_branch": SOURCE_BRANCH,
        "merge_commit": merge_commit,
        "post_merge_head": current_head,
        "pre_merge_main_tip": pre_merge_main_tip,
        "merged_source_tip": merged_source_tip,
        "track03_repo_authority_now_canonical": True,
        "package_promotion_still_deferred": True,
        "worktree_clean_after_merge": True,
        "first_post_merge_authoritative_lane": str(post_merge_fork.get("first_lane_to_promote", "")).strip(),
        "next_lawful_move": NEXT_MOVE,
    }

    report = common.report_lines(
        "Cohort0 Post-F Track 03 Post-Merge Closeout Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Post-merge status: `{POST_MERGE_STATUS}`",
            f"- Current canonical head: `{current_head}`",
            f"- Merge commit: `{merge_commit}`",
            f"- Pre-merge main tip: `{pre_merge_main_tip}`",
            f"- Merged source tip: `{merged_source_tip}`",
            "- Track 03 repo authority is now canonical on `main`.",
            "- Package promotion remains deferred by explicit law.",
            f"- First post-merge authoritative lane: `{post_merge_fork.get('first_lane_to_promote', '')}`",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"snapshot": snapshot, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    decision_packet_path: Path,
    decision_receipt_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: Track 03 post-merge closeout must run on {REQUIRED_BRANCH}, got {branch_name}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: Track 03 post-merge closeout requires a clean worktree")

    decision_packet = common.load_json_required(root, decision_packet_path, label="Track 03 protected merge decision packet")
    decision_receipt = common.load_json_required(root, decision_receipt_path, label="Track 03 protected merge decision receipt")
    common.ensure_pass(decision_packet, label="Track 03 protected merge decision packet")
    common.ensure_pass(decision_receipt, label="Track 03 protected merge decision receipt")

    if str(decision_receipt.get("decision_outcome", "")).strip() != "MERGE_APPROVED__PACKAGE_PROMOTION_DEFERRED":
        raise RuntimeError("FAIL_CLOSED: post-merge closeout requires the merge-approved/package-promotion-deferred verdict")
    if str(decision_receipt.get("next_lawful_move", "")).strip() != "EXECUTE_PROTECTED_MERGE_TO_MAIN__PACKAGE_PROMOTION_STILL_DEFERRED":
        raise RuntimeError("FAIL_CLOSED: protected merge decision did not authorize the executed repo-only merge path")

    current_head = _git_rev_parse(root, "HEAD")
    merge_commit = _latest_first_parent_merge_commit(root)
    parents = _git_commit_parents(root, merge_commit)
    head_commit = parents[0]
    pre_merge_main_tip = parents[1]
    merged_source_tip = parents[2]
    source_tip_expected = _git_rev_parse(root, SOURCE_BRANCH)
    if merged_source_tip != source_tip_expected:
        raise RuntimeError("FAIL_CLOSED: current merge commit second parent does not match the approved source branch tip")

    outputs = build_outputs(
        current_head=current_head,
        merge_commit=merge_commit,
        head_commit=head_commit,
        pre_merge_main_tip=pre_merge_main_tip,
        merged_source_tip=merged_source_tip,
        merge_message=_git_message(root, merge_commit),
        decision_packet=decision_packet,
        decision_receipt=decision_receipt,
    )

    common.write_outputs(
        packet_path=(reports_root / OUTPUT_SNAPSHOT).resolve(),
        receipt_path=(reports_root / OUTPUT_RECEIPT).resolve(),
        report_path=(reports_root / OUTPUT_REPORT).resolve(),
        packet=outputs["snapshot"],
        receipt=outputs["receipt"],
        report_text=str(outputs["report"]),
    )
    return {
        "post_merge_status": POST_MERGE_STATUS,
        "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(),
        "next_lawful_move": NEXT_MOVE,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Freeze the Track 03 post-merge canonical closeout state on main.")
    parser.add_argument(
        "--decision-packet",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_protected_merge_and_canonical_promotion_decision_packet.json",
    )
    parser.add_argument(
        "--decision-receipt",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_protected_merge_and_canonical_promotion_decision_receipt.json",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        decision_packet_path=common.resolve_path(root, args.decision_packet),
        decision_receipt_path=common.resolve_path(root, args.decision_receipt),
    )
    print(result["post_merge_status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
