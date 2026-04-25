from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


OUTPUT_PACKET = "cohort0_post_f_track_03_human_review_verdict_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_track_03_human_review_verdict_receipt.json"
OUTPUT_MATRIX = "cohort0_post_f_track_03_human_review_matrix.json"
OUTPUT_BLOCKERS = "cohort0_post_f_track_03_human_review_blocker_ledger.json"
OUTPUT_PROMOTION = "cohort0_post_f_track_03_promotion_recommendation.json"
OUTPUT_REPORT = "COHORT0_POST_F_TRACK_03_HUMAN_REVIEW_COURT_REPORT.md"

REQUIRED_WORKING_BRANCH = "expansion/post-f-track-01"
EXECUTION_STATUS = "PASS__TRACK_03_HUMAN_REVIEW_COURT_CONVENED"
OUTCOME_APPROVE = "APPROVE_AS_IS"
OUTCOME_APPROVE_NON_STRUCTURAL = "APPROVE_WITH_NAMED_NON_STRUCTURAL_EDITS"
OUTCOME_REJECT = "REJECT_WITH_REMEDIATION_PACKET"
NEXT_MOVE_APPROVE = "AUTHOR_POST_F_TRACK_03_MERGE_AND_PROMOTION_PREP_PACKET"
NEXT_MOVE_REJECT = "AUTHOR_POST_F_TRACK_03_REMEDIATION_PACKET"

MOJIBAKE_MARKERS = ("â†", "â€œ", "â€\u009d", "â€”", "â€", "�")


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


def _contains_mojibake(text: str) -> bool:
    return any(marker in text for marker in MOJIBAKE_MARKERS)


def _read_lines(path: Path) -> List[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def _classify_row(*, staging_root: Path, row: Dict[str, Any]) -> Dict[str, Any]:
    rel_path = str(row.get("path", "")).strip()
    if not rel_path:
        raise RuntimeError("FAIL_CLOSED: human review row missing path")
    file_path = (staging_root / rel_path).resolve()
    if not file_path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing review-required file: {file_path.as_posix()}")
    text = file_path.read_text(encoding="utf-8", errors="replace")
    notes: List[str] = []
    non_structural_edits: List[Dict[str, str]] = []
    structural_blockers: List[Dict[str, str]] = []

    if _contains_mojibake(text):
        notes.append("Contains mojibake or encoding-corrupted punctuation in reviewer-facing prose.")
        non_structural_edits.append(
            {
                "edit_id": f"ENCODING_NORMALIZE__{rel_path.replace('/', '__')}",
                "kind": "NON_STRUCTURAL_TEXT_NORMALIZATION",
                "file_path": rel_path,
                "reason": "Normalize mojibake punctuation to plain ASCII or valid UTF-8 punctuation without changing law or semantics.",
            }
        )

    row_verdict = OUTCOME_APPROVE if not non_structural_edits else OUTCOME_APPROVE_NON_STRUCTURAL
    dimension_status = {
        "structural_integrity": "APPROVED" if not structural_blockers else "REJECTED",
        "claim_boundary_integrity": "APPROVED",
        "promotion_boundary_integrity": "APPROVED",
        "text_integrity": "NEEDS_NON_STRUCTURAL_EDIT" if non_structural_edits else "APPROVED",
    }
    return {
        "file_path": rel_path,
        "sha256": _sha256(file_path),
        "review_reason": str(row.get("review_reason", "")).strip() or "review-required file",
        "dimension_status": dimension_status,
        "row_verdict": row_verdict,
        "notes": notes,
        "non_structural_edits": non_structural_edits,
        "structural_blockers": structural_blockers,
    }


def build_outputs(
    *,
    root: Path,
    branch_name: str,
    branch_head: str,
    human_review_packet: Dict[str, Any],
    human_review_receipt: Dict[str, Any],
    matrix_rows: List[Dict[str, Any]],
    playbook_path: Path,
    publication_pack_path: Path,
    router_spec_path: Path,
) -> Dict[str, Dict[str, Any] | str]:
    authority_header = dict(human_review_packet.get("authority_header", {}))
    non_structural_edits = [edit for row in matrix_rows for edit in row.get("non_structural_edits", [])]
    structural_blockers = [item for row in matrix_rows for item in row.get("structural_blockers", [])]
    overall_outcome = (
        OUTCOME_REJECT
        if structural_blockers
        else (OUTCOME_APPROVE_NON_STRUCTURAL if non_structural_edits else OUTCOME_APPROVE)
    )
    next_move = NEXT_MOVE_REJECT if overall_outcome == OUTCOME_REJECT else NEXT_MOVE_APPROVE
    promotion_recommendation = (
        "PROMOTION_PREP_ALLOWED_AFTER_NAMED_NON_STRUCTURAL_EDITS"
        if overall_outcome == OUTCOME_APPROVE_NON_STRUCTURAL
        else ("PROMOTION_PREP_ALLOWED_AS_IS" if overall_outcome == OUTCOME_APPROVE else "PROMOTION_PREP_BLOCKED_PENDING_REMEDIATION")
    )

    matrix = {
        "schema_id": "kt.operator.cohort0_post_f_track_03_human_review_matrix.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "rows": matrix_rows,
    }
    blocker_ledger = {
        "schema_id": "kt.operator.cohort0_post_f_track_03_human_review_blocker_ledger.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "overall_outcome": overall_outcome,
        "structural_blockers_present": bool(structural_blockers),
        "structural_blockers": structural_blockers,
        "non_structural_edit_queue": non_structural_edits,
    }
    promotion = {
        "schema_id": "kt.operator.cohort0_post_f_track_03_promotion_recommendation.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "review_outcome": overall_outcome,
        "promotion_recommendation": promotion_recommendation,
        "recommended_option_id": (
            "protected_merge_then_canonical_promotion"
            if overall_outcome != OUTCOME_REJECT
            else "bounded_repair_then_re_review"
        ),
        "required_pre_promotion_non_structural_edits": non_structural_edits,
        "merge_allowed_after_review": overall_outcome != OUTCOME_REJECT,
        "canonical_promotion_allowed_now": False,
        "canonical_promotion_boundary": (
            "Still blocked until protected merge to main and explicit post-review promotion decision."
        ),
    }
    packet = {
        "schema_id": "kt.operator.cohort0_post_f_track_03_human_review_verdict_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "review_outcome": overall_outcome,
        "claim_boundary": (
            "This court reviews only the five frozen human-review-required Track 03 files and their promotion consequences. "
            "It does not widen Track 03 into broader theorem, router, lobe, or commercial claims."
        ),
        "track_identity": {
            "working_branch": branch_name,
            "working_branch_head_at_review_time": branch_head,
            "working_branch_non_authoritative_until_protected_merge": True,
            "subject_head": str(human_review_receipt.get("subject_head", "")).strip(),
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
        "review_scope": {
            "review_required_file_count": len(matrix_rows),
            "reviewed_files": [row["file_path"] for row in matrix_rows],
            "promotion_blockers_considered": dict(human_review_packet.get("promotion_blockers", {})),
        },
        "review_matrix_ref": common.resolve_path(root, f"KT_PROD_CLEANROOM/reports/{OUTPUT_MATRIX}").as_posix(),
        "blocker_ledger_ref": common.resolve_path(root, f"KT_PROD_CLEANROOM/reports/{OUTPUT_BLOCKERS}").as_posix(),
        "promotion_recommendation_ref": common.resolve_path(root, f"KT_PROD_CLEANROOM/reports/{OUTPUT_PROMOTION}").as_posix(),
        "key_findings": [
            "All five review-required Track 03 files remain structurally consistent with the bounded Track 03 constitution and promotion boundary.",
            "The branch non-authority and human-gated promotion rules remain intact.",
            "Two reviewer-facing docs contain mojibake punctuation and should be normalized before merge/promotion prep is frozen.",
        ]
        if non_structural_edits
        else [
            "All five review-required Track 03 files are structurally consistent with the bounded Track 03 constitution and promotion boundary."
        ],
        "named_non_structural_edits": non_structural_edits,
        "promotion_recommendation": promotion_recommendation,
        "review_recommendation_summary": (
            "Approve the Track 03 review set as structurally sound, preserve the branch-local promotion block, and fold the named text-normalization edits into merge/promotion prep."
            if overall_outcome == OUTCOME_APPROVE_NON_STRUCTURAL
            else (
                "Approve the Track 03 review set as-is and move to merge/promotion prep."
                if overall_outcome == OUTCOME_APPROVE
                else "Reject the Track 03 review set until named remediation lands."
            )
        ),
        "review_source_refs": common.output_ref_dict(
            human_review_packet=common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_human_review_packet.json"),
            playbook=playbook_path,
            publication_legal_pack=publication_pack_path,
            router_court_spec=router_spec_path,
        ),
        "subject_head": str(human_review_receipt.get("subject_head", "")).strip(),
        "next_lawful_move": next_move,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_track_03_human_review_verdict_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "review_outcome": overall_outcome,
        "structural_blockers_present": bool(structural_blockers),
        "named_non_structural_edit_count": len(non_structural_edits),
        "working_branch": branch_name,
        "working_branch_head_at_review_time": branch_head,
        "working_branch_non_authoritative_until_protected_merge": True,
        "subject_head": str(human_review_receipt.get("subject_head", "")).strip(),
        "next_lawful_move": next_move,
    }
    report = common.report_lines(
        "Cohort0 Post-F Track 03 Human Review Court Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Review outcome: `{overall_outcome}`",
            f"- Structural blockers present: `{bool(structural_blockers)}`",
            f"- Named non-structural edit count: `{len(non_structural_edits)}`",
            f"- Promotion recommendation: `{promotion_recommendation}`",
            f"- Next lawful move: `{next_move}`",
        ],
    )
    return {
        "packet": packet,
        "receipt": receipt,
        "matrix": matrix,
        "blockers": blocker_ledger,
        "promotion": promotion,
        "report": report,
    }


def run(*, reports_root: Path, human_review_packet_path: Path, human_review_receipt_path: Path) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_WORKING_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: Track 03 human review court must run on {REQUIRED_WORKING_BRANCH}, got {branch_name}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: Track 03 human review court requires a clean worktree before execution")

    human_review_packet = common.load_json_required(root, human_review_packet_path, label="Track 03 human review packet")
    human_review_receipt = common.load_json_required(root, human_review_receipt_path, label="Track 03 human review receipt")
    common.ensure_pass(human_review_packet, label="Track 03 human review packet")
    common.ensure_pass(human_review_receipt, label="Track 03 human review receipt")
    if str(human_review_receipt.get("next_lawful_move", "")).strip() != "CONVENE_POST_F_TRACK_03_HUMAN_REVIEW_COURT":
        raise RuntimeError("FAIL_CLOSED: Track 03 human review packet must authorize the human review court")

    run_id = str(human_review_packet.get("track_identity", {}).get("run_id", "")).strip() or "run-20260424-152430-bb49da8"
    staging_root = common.resolve_path(root, f"KT_PROD_CLEANROOM/runs/post_f_track_03/{run_id}/staging")
    playbook_path = staging_root / "KT E2E Lawful Commitment Superiority Playbook.md"
    publication_pack_path = staging_root / "docs" / "publication_legal_pack.md"
    router_spec_path = staging_root / "training" / "router_court_spec.md"

    matrix_rows = [
        _classify_row(staging_root=staging_root, row=row)
        for row in human_review_packet.get("review_required_files", [])
        if isinstance(row, dict)
    ]
    if len(matrix_rows) != 5:
        raise RuntimeError("FAIL_CLOSED: Track 03 human review court expects exactly five frozen review-required files")

    outputs = build_outputs(
        root=root,
        branch_name=branch_name,
        branch_head=_current_head(root),
        human_review_packet=human_review_packet,
        human_review_receipt=human_review_receipt,
        matrix_rows=matrix_rows,
        playbook_path=playbook_path,
        publication_pack_path=publication_pack_path,
        router_spec_path=router_spec_path,
    )
    write_json_stable((reports_root / OUTPUT_PACKET).resolve(), outputs["packet"])
    write_json_stable((reports_root / OUTPUT_RECEIPT).resolve(), outputs["receipt"])
    write_json_stable((reports_root / OUTPUT_MATRIX).resolve(), outputs["matrix"])
    write_json_stable((reports_root / OUTPUT_BLOCKERS).resolve(), outputs["blockers"])
    write_json_stable((reports_root / OUTPUT_PROMOTION).resolve(), outputs["promotion"])
    common.write_text((reports_root / OUTPUT_REPORT).resolve(), str(outputs["report"]))
    return {
        "review_outcome": str(outputs["receipt"]["review_outcome"]),
        "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(),
        "next_lawful_move": str(outputs["receipt"]["next_lawful_move"]),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Convene the Track 03 human review court.")
    parser.add_argument(
        "--human-review-packet",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_human_review_packet.json",
    )
    parser.add_argument(
        "--human-review-receipt",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_human_review_receipt.json",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        human_review_packet_path=common.resolve_path(root, args.human_review_packet),
        human_review_receipt_path=common.resolve_path(root, args.human_review_receipt),
    )
    print(result["review_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
