from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_post_f_track_03_human_review_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_track_03_human_review_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_TRACK_03_HUMAN_REVIEW_REPORT.md"

TRACK_ID = "POST_F_TRACK_03_COMPLETED_E2E_EXECUTION"
REQUIRED_WORKING_BRANCH = "expansion/post-f-track-01"
DEFAULT_RUN_ID = "run-20260424-152430-bb49da8"
EXECUTION_STATUS = "PASS__TRACK_03_HUMAN_REVIEW_PACKET_BOUND"
REVIEW_OUTCOME = "TRACK_03_HUMAN_REVIEW_PACKET_BOUND__PROMOTION_STILL_PENDING"
NEXT_MOVE = "CONVENE_POST_F_TRACK_03_HUMAN_REVIEW_COURT"


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


def _require_status(payload: Dict[str, Any], *, label: str, expected: str) -> None:
    actual = str(payload.get("status", "")).strip()
    if actual != expected:
        raise RuntimeError(f"FAIL_CLOSED: {label} must have status {expected}, got {actual or 'MISSING'}")


def _require_current_head_receipt(payload: Dict[str, Any]) -> None:
    current_branch = str(payload.get("current_branch", "")).strip()
    current_git_head = str(payload.get("current_git_head", "")).strip()
    frozen_manifest_digest = str(payload.get("frozen_manifest_digest", "")).strip()
    if not current_branch:
        raise RuntimeError("FAIL_CLOSED: Track 03 current-head receipt missing current_branch")
    if not current_git_head:
        raise RuntimeError("FAIL_CLOSED: Track 03 current-head receipt missing current_git_head")
    if not frozen_manifest_digest:
        raise RuntimeError("FAIL_CLOSED: Track 03 current-head receipt missing frozen_manifest_digest")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _scan_human_review_required_files(staging_root: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for path in sorted(p for p in staging_root.rglob("*") if p.is_file()):
        try:
            first_lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()[:10]
        except Exception:
            first_lines = []
        if not any("human_review_required: true" in line for line in first_lines):
            continue
        rows.append(
            {
                "path": path.relative_to(staging_root).as_posix(),
                "sha256": _sha256(path),
                "review_reason": "file header carries human_review_required: true",
                "review_state": "UNREVIEWED__EXPLICIT_HUMAN_REVIEW_REQUIRED",
                "automation_state": "SKIPPED_BY_AUTOMATION_UNTIL_REVIEW",
            }
        )
    return rows


def _promotion_options() -> List[Dict[str, Any]]:
    return [
        {
            "option_id": "retain_branch_local_freeze_only",
            "status": "AVAILABLE_NOW",
            "changes_canonical_truth": False,
            "description": (
                "Keep Track 03 as execution-complete but branch-local, preserve the promotion block, "
                "and treat the package as reviewed-but-not-canonically adopted."
            ),
            "requires": [
                "explicit operator decision to remain non-authoritative",
                "no stage_and_promote execution",
            ],
        },
        {
            "option_id": "protected_merge_then_canonical_promotion",
            "status": "PENDING_HUMAN_REVIEW_AND_MERGE",
            "changes_canonical_truth": True,
            "description": (
                "Complete human review, merge the authoritative branch through the protected path, "
                "then run stage_and_promote.sh from the canonical line under explicit operator decision."
            ),
            "requires": [
                "review completion for all human_review_required files",
                "protected-branch merge to main",
                "clean tracked state on canonical branch",
                "explicit promotion decision after review",
            ],
        },
        {
            "option_id": "bounded_repair_then_re_review",
            "status": "AVAILABLE_IF_REVIEW_FINDS_DEFECT",
            "changes_canonical_truth": False,
            "description": (
                "If human review finds a bounded defect, emit a repair packet, preserve non-authoritative status, "
                "and reconvene review instead of forcing promotion."
            ),
            "requires": [
                "review finding naming the bounded defect",
                "tracked repair under fail-closed discipline",
                "new review packet or superseding review receipt",
            ],
        },
    ]


def build_outputs(
    *,
    root: Path,
    branch_name: str,
    branch_head: str,
    final_summary_packet: Dict[str, Any],
    final_summary_receipt: Dict[str, Any],
    promotion_block_receipt: Dict[str, Any],
    reconciliation_packet: Dict[str, Any],
    validation_matrix: Dict[str, Any],
    counted_path_receipt: Dict[str, Any],
    task_summary: Dict[str, Any],
    current_head_receipt: Dict[str, Any],
    playbook_path: Path,
    review_required_files: List[Dict[str, Any]],
    proof_bundle_path: Path,
    proof_signature_path: Path,
) -> Dict[str, Dict[str, Any] | str]:
    authority_header = dict(final_summary_packet.get("authority_header", {}))
    human_review_paths = [row["path"] for row in review_required_files]
    block_reasons = list(promotion_block_receipt.get("block_reasons", []))
    proof_bundle_sha = _sha256(proof_bundle_path)
    proof_signature_sha = _sha256(proof_signature_path)
    execution_head = str(current_head_receipt.get("current_git_head", "")).strip()

    packet = {
        "schema_id": "kt.operator.cohort0_post_f_track_03_human_review_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "review_outcome": REVIEW_OUTCOME,
        "claim_boundary": (
            "This packet freezes the Track 03 human-review surface only. It does not promote Track 03, does not "
            "override canonical authority, and does not widen Track 03 into broader router, lobe, platform, or commercial claims."
        ),
        "track_identity": {
            "track_id": TRACK_ID,
            "run_id": DEFAULT_RUN_ID,
            "working_branch": branch_name,
            "working_branch_head_at_review_packet_time": branch_head,
            "working_branch_non_authoritative_until_protected_merge": True,
            "track03_execution_complete_in_branch_scope": True,
        },
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
        "review_required_files": review_required_files,
        "review_state_partition": {
            "review_complete": False,
            "reviewed_items": [],
            "unreviewed_items": human_review_paths,
            "completion_rule": (
                "Human review is complete only when each review-required file has an explicit reviewed verdict "
                "captured in a superseding review receipt or promotion-decision artifact."
            ),
        },
        "promotion_blockers": {
            "promotion_blocked": True,
            "multisig_threshold_satisfied": bool(promotion_block_receipt.get("multisig_threshold_satisfied", False)),
            "block_reasons": block_reasons,
            "automation_skip_rule": "Files marked human_review_required: true remain outside auto-promotion.",
            "non_authoritative_until_merge_rule": (
                "Branch-local execution truth may be reviewed and preserved, but it may not become canonical "
                "until protected merge to main and explicit promotion decision."
            ),
        },
        "review_evidence_bundle": {
            "playbook_ref": playbook_path.resolve().as_posix(),
            "task_summary_ref": common.resolve_path(
                root,
                f"KT_PROD_CLEANROOM/runs/post_f_track_03/{DEFAULT_RUN_ID}/staging/staging/task_summary.json",
            ).as_posix(),
            "reconciliation_packet_ref": common.resolve_path(
                root,
                f"KT_PROD_CLEANROOM/runs/post_f_track_03/{DEFAULT_RUN_ID}/artifacts/reconciliation_packet.json",
            ).as_posix(),
            "validation_matrix_ref": common.resolve_path(
                root,
                f"KT_PROD_CLEANROOM/runs/post_f_track_03/{DEFAULT_RUN_ID}/artifacts/validation_matrix.json",
            ).as_posix(),
            "counted_path_receipt_ref": common.resolve_path(
                root,
                f"KT_PROD_CLEANROOM/runs/post_f_track_03/{DEFAULT_RUN_ID}/artifacts/counted_path_receipt.json",
            ).as_posix(),
            "promotion_block_receipt_ref": common.resolve_path(
                root,
                f"KT_PROD_CLEANROOM/runs/post_f_track_03/{DEFAULT_RUN_ID}/artifacts/promotion_block_receipt.json",
            ).as_posix(),
            "current_head_receipt_ref": common.resolve_path(
                root,
                f"KT_PROD_CLEANROOM/runs/post_f_track_03/{DEFAULT_RUN_ID}/staging/reports/cohort0_current_head_receipt.json",
            ).as_posix(),
            "proof_bundle_ref": proof_bundle_path.resolve().as_posix(),
            "proof_bundle_sha256": proof_bundle_sha,
            "proof_signature_ref": proof_signature_path.resolve().as_posix(),
            "proof_signature_sha256": proof_signature_sha,
            "execution_head_bound_in_current_head_receipt": execution_head,
        },
        "promotion_options": _promotion_options(),
        "review_guidance": {
            "task_summary_next_steps": list(task_summary.get("next_steps", [])),
            "focus_points": [
                "Confirm the stale manifest-row defect remained preserved and superseded explicitly.",
                "Confirm smoke-before-counted discipline and exactly one counted receipt on the reconciled manifest.",
                "Confirm human_review_required files were not auto-promoted.",
                "Confirm branch-local status remains non-authoritative until merge.",
            ],
            "counted_path_status": str(counted_path_receipt.get("status", "")).strip(),
            "validation_status": str(validation_matrix.get("status", "")).strip(),
            "reconciliation_status": str(reconciliation_packet.get("status", "")).strip(),
        },
        "subject_head": execution_head,
        "next_lawful_move": NEXT_MOVE,
    }

    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_track_03_human_review_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "review_outcome": REVIEW_OUTCOME,
        "working_branch": branch_name,
        "working_branch_head_at_review_packet_time": branch_head,
        "working_branch_non_authoritative_until_protected_merge": True,
        "review_required_file_count": len(review_required_files),
        "promotion_blocked": True,
        "subject_head": execution_head,
        "next_lawful_move": NEXT_MOVE,
    }

    report = common.report_lines(
        "Cohort0 Post-F Track 03 Human Review Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Review outcome: `{REVIEW_OUTCOME}`",
            f"- Working branch: `{branch_name}`",
            f"- Review-required file count: `{len(review_required_files)}`",
            f"- Execution head: `{execution_head}`",
            f"- Promotion blocked: `True`",
            f"- Multisig threshold satisfied: `{promotion_block_receipt.get('multisig_threshold_satisfied', False)}`",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    final_summary_packet_path: Path,
    final_summary_receipt_path: Path,
    run_root: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_WORKING_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: Track 03 human review packet must run on {REQUIRED_WORKING_BRANCH}, got {branch_name}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: Track 03 human review packet requires a clean worktree before execution")

    final_summary_packet = common.load_json_required(root, final_summary_packet_path, label="Track 03 final summary packet")
    final_summary_receipt = common.load_json_required(root, final_summary_receipt_path, label="Track 03 final summary receipt")
    promotion_block_receipt = common.load_json_required(root, run_root / "artifacts" / "promotion_block_receipt.json", label="Track 03 promotion block receipt")
    reconciliation_packet = common.load_json_required(root, run_root / "artifacts" / "reconciliation_packet.json", label="Track 03 reconciliation packet")
    validation_matrix = common.load_json_required(root, run_root / "artifacts" / "validation_matrix.json", label="Track 03 validation matrix")
    counted_path_receipt = common.load_json_required(root, run_root / "artifacts" / "counted_path_receipt.json", label="Track 03 counted path receipt")
    current_head_receipt = common.load_json_required(root, run_root / "staging" / "reports" / "cohort0_current_head_receipt.json", label="Track 03 current head receipt")
    task_summary = common.load_json_required(root, run_root / "staging" / "staging" / "task_summary.json", label="Track 03 task summary")
    playbook_path = common.resolve_path(root, run_root / "staging" / "KT E2E Lawful Commitment Superiority Playbook.md")
    proof_bundle_path = common.resolve_path(root, run_root / "staging" / "bundle" / f"proof_bundle_{DEFAULT_RUN_ID}.tar.gz")
    proof_signature_path = common.resolve_path(root, run_root / "staging" / "signatures" / f"proof_bundle_{DEFAULT_RUN_ID}.sig")

    common.ensure_pass(final_summary_packet, label="Track 03 final summary packet")
    common.ensure_pass(final_summary_receipt, label="Track 03 final summary receipt")
    _require_status(promotion_block_receipt, label="Track 03 promotion block receipt", expected="BLOCKED")
    _require_status(reconciliation_packet, label="Track 03 reconciliation packet", expected="PASS_READY_FOR_VALIDATION")
    _require_status(validation_matrix, label="Track 03 validation matrix", expected="PASS")
    _require_status(counted_path_receipt, label="Track 03 counted path receipt", expected="PASS")
    _require_current_head_receipt(current_head_receipt)

    if str(final_summary_receipt.get("next_lawful_move", "")).strip() != "AUTHOR_POST_F_TRACK_03_HUMAN_REVIEW_PACKET":
        raise RuntimeError("FAIL_CLOSED: Track 03 final summary does not authorize the human-review packet as the next move")
    if not bool(final_summary_receipt.get("working_branch_non_authoritative_until_protected_merge", False)):
        raise RuntimeError("FAIL_CLOSED: Track 03 human review packet requires non-authoritative branch status preserved")
    if str(current_head_receipt.get("current_branch", "")).strip() != branch_name:
        raise RuntimeError("FAIL_CLOSED: Track 03 current-head receipt branch does not match current branch")
    if not playbook_path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing Track 03 playbook: {playbook_path.as_posix()}")
    if not proof_bundle_path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing Track 03 proof bundle: {proof_bundle_path.as_posix()}")
    if not proof_signature_path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing Track 03 proof signature: {proof_signature_path.as_posix()}")

    review_required_files = _scan_human_review_required_files(common.resolve_path(root, run_root / "staging"))
    if not review_required_files:
        raise RuntimeError("FAIL_CLOSED: Track 03 human review packet requires at least one human_review_required file")
    if "KT E2E Lawful Commitment Superiority Playbook.md" not in {row["path"] for row in review_required_files}:
        raise RuntimeError("FAIL_CLOSED: Track 03 playbook must remain in the review-required set")

    outputs = build_outputs(
        root=root,
        branch_name=branch_name,
        branch_head=_current_head(root),
        final_summary_packet=final_summary_packet,
        final_summary_receipt=final_summary_receipt,
        promotion_block_receipt=promotion_block_receipt,
        reconciliation_packet=reconciliation_packet,
        validation_matrix=validation_matrix,
        counted_path_receipt=counted_path_receipt,
        task_summary=task_summary,
        current_head_receipt=current_head_receipt,
        playbook_path=playbook_path,
        review_required_files=review_required_files,
        proof_bundle_path=proof_bundle_path,
        proof_signature_path=proof_signature_path,
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
        "review_outcome": REVIEW_OUTCOME,
        "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(),
        "next_lawful_move": NEXT_MOVE,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Author the Track 03 human review packet.")
    parser.add_argument(
        "--track03-final-summary-packet",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_final_summary_packet.json",
    )
    parser.add_argument(
        "--track03-final-summary-receipt",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_final_summary_receipt.json",
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
        final_summary_packet_path=common.resolve_path(root, args.track03_final_summary_packet),
        final_summary_receipt_path=common.resolve_path(root, args.track03_final_summary_receipt),
        run_root=common.resolve_path(root, args.run_root),
    )
    print(result["review_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
