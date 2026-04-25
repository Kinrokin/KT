from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_post_f_track_03_final_summary_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_track_03_final_summary_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_TRACK_03_FINAL_SUMMARY_REPORT.md"

TRACK_ID = "POST_F_TRACK_03_COMPLETED_E2E_EXECUTION"
REQUIRED_WORKING_BRANCH = "expansion/post-f-track-01"
DEFAULT_RUN_ID = "run-20260424-152430-bb49da8"
EXECUTION_STATUS = "PASS__TRACK_03_FINAL_SUMMARY_PACKET_BOUND"
SUMMARY_OUTCOME = "TRACK_03_EXECUTION_CLOSEOUT_FROZEN__PROMOTION_BOUNDARY_EXPLICIT"
NEXT_MOVE = "AUTHOR_POST_F_TRACK_03_HUMAN_REVIEW_PACKET"


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


def _decision_summary(runtime_receipt: Dict[str, Any]) -> Dict[str, Any]:
    results = runtime_receipt.get("results", [])
    if not isinstance(results, list) or not results:
        raise RuntimeError("FAIL_CLOSED: counted runtime receipt must contain non-empty results")
    commit_rows = [row for row in results if str(row.get("decision_label", "")).strip() == "commit"]
    defer_rows = [row for row in results if str(row.get("decision_label", "")).strip() == "defer"]
    providers = sorted({str(call.get("provider", "")).strip() for call in runtime_receipt.get("provider_calls", []) if str(call.get("provider", "")).strip()})
    why_not_counts: Dict[str, int] = {}
    for row in results:
        for code in row.get("why_not", []):
            key = str(code).strip()
            why_not_counts[key] = why_not_counts.get(key, 0) + 1
    return {
        "row_count": len(results),
        "commit_count": len(commit_rows),
        "defer_count": len(defer_rows),
        "provider_set": providers,
        "why_not_counts": dict(sorted(why_not_counts.items())),
    }


def build_outputs(
    *,
    root: Path,
    branch_name: str,
    branch_head: str,
    track02_packet: Dict[str, Any],
    track02_receipt: Dict[str, Any],
    intake_receipt: Dict[str, Any],
    repo_snapshot: Dict[str, Any],
    materialization_receipt: Dict[str, Any],
    reconciliation_packet: Dict[str, Any],
    validation_matrix: Dict[str, Any],
    smoke_receipt: Dict[str, Any],
    counted_receipt: Dict[str, Any],
    promotion_block_receipt: Dict[str, Any],
    current_head_receipt: Dict[str, Any],
    counted_runtime_receipt: Dict[str, Any],
    proof_bundle_path: Path,
    proof_bundle_sha_path: Path,
    proof_signature_path: Path,
    quarantine_note_path: Path,
) -> Dict[str, Dict[str, Any] | str]:
    authority_header = dict(track02_packet.get("authority_header", {}))
    decision_summary = _decision_summary(counted_runtime_receipt)
    execution_head = str(current_head_receipt.get("current_git_head", "")).strip()
    manifest_digest = str(counted_receipt.get("manifest_digest", "")).strip()
    bundle_sha = file_sha256(proof_bundle_path)
    bundle_sha_line = proof_bundle_sha_path.read_text(encoding="utf-8").split()[0].strip()
    if bundle_sha != bundle_sha_line:
        raise RuntimeError("FAIL_CLOSED: proof bundle sha file does not match bundle bytes")

    english_brief = {
        "bottom_line": (
            "Track 03 is execution-valid in branch scope. The handoff bundle survived intake, lawful defect detection, "
            "repair, smoke-before-counted discipline, deterministic bundle reproduction, one counted H1 lane, and promotion fail-close."
        ),
        "defect_read": (
            "The most important event was not first-pass greenness. E02 failed honestly on one stale external manifest row, "
            "that defect was quarantined and superseded explicitly, and the execution continued from a reconciled tracked staging tree."
        ),
        "counted_path_read": (
            "One counted H1 lane ran successfully under a refreshed current-head receipt, a reconciled manifest digest, and mock signing/transparency defaults."
        ),
        "promotion_read": (
            "Promotion remains intentionally blocked. Multisig threshold was satisfied, but branch non-authority and human-review requirements still prevent canonical uplift."
        ),
    }

    packet = {
        "schema_id": "kt.operator.cohort0_post_f_track_03_final_summary_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "summary_outcome": SUMMARY_OUTCOME,
        "claim_boundary": (
            "This packet freezes Track 03 as a branch-local execution closeout. It does not reopen Track 02, does not widen Gate F, "
            "does not claim full-system ratification, and does not convert one counted H1 lane into broad capability or commercial proof."
        ),
        "track_identity": {
            "track_id": TRACK_ID,
            "track_name": "Track 03 Completed E2E Execution",
            "run_id": DEFAULT_RUN_ID,
            "track_status": "EXECUTION_COMPLETE__PROMOTION_STILL_GATED",
            "working_branch": branch_name,
            "working_branch_head_at_summary_time": branch_head,
            "working_branch_non_authoritative_until_protected_merge": True,
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
        "track02_dependency_header": {
            "track02_summary_outcome": str(track02_receipt.get("summary_outcome", "")).strip(),
            "track02_subject_head": str(track02_receipt.get("subject_head", "")).strip(),
            "track02_next_move_before_track03": str(track02_receipt.get("next_lawful_move", "")).strip(),
        },
        "phase_summary": {
            "E00_bundle_integrity_intake": str(intake_receipt.get("status", "")).strip(),
            "E01_repo_safety_snapshot": str(repo_snapshot.get("status", "")).strip(),
            "E02_materialization": str(materialization_receipt.get("status", "")).strip(),
            "E03_reconciliation": str(reconciliation_packet.get("status", "")).strip(),
            "E05_validation_and_counted_path": str(validation_matrix.get("status", "")).strip(),
            "E06_promotion_control": str(promotion_block_receipt.get("status", "")).strip(),
        },
        "defect_and_repair_summary": {
            "materialization_failed_honestly": str(materialization_receipt.get("status", "")).strip() == "FAIL",
            "materialization_failure_surface": list(materialization_receipt.get("mismatched_files", [])),
            "quarantine_note_ref": quarantine_note_path.resolve().as_posix(),
            "reconciliation_repair_status": str(reconciliation_packet.get("status", "")).strip(),
            "hardening_changes": list(reconciliation_packet.get("hardening_changes", [])),
            "superseded_surfaces": list(reconciliation_packet.get("superseded", [])),
        },
        "execution_closeout": {
            "execution_head_bound_in_current_head_receipt": execution_head,
            "current_head_receipt_branch": str(current_head_receipt.get("current_branch", "")).strip(),
            "frozen_manifest_digest": manifest_digest,
            "smoke_status": str(smoke_receipt.get("status", "")).strip(),
            "counted_status": str(counted_receipt.get("status", "")).strip(),
            "counted_decision_summary": decision_summary,
            "proof_bundle_sha256": bundle_sha,
            "proof_bundle_sha_file_matches": True,
            "proof_bundle_ref": proof_bundle_path.resolve().as_posix(),
            "proof_bundle_sha_ref": proof_bundle_sha_path.resolve().as_posix(),
            "proof_signature_ref": proof_signature_path.resolve().as_posix(),
            "mock_transparency_index_ref": common.resolve_path(root, f"KT_PROD_CLEANROOM/runs/post_f_track_03/{DEFAULT_RUN_ID}/staging/mock_rekor/index.json").as_posix(),
        },
        "validation_summary": {
            "validation_matrix_status": str(validation_matrix.get("status", "")).strip(),
            "checks": list(validation_matrix.get("checks", [])),
            "counted_path_rule": str(validation_matrix.get("counted_path_rule", "")).strip(),
        },
        "promotion_boundary": {
            "promotion_blocked": str(promotion_block_receipt.get("status", "")).strip() == "BLOCKED",
            "multisig_threshold_satisfied": bool(promotion_block_receipt.get("multisig_threshold_satisfied", False)),
            "promotion_attempted": bool(promotion_block_receipt.get("promotion_attempted", False)),
            "block_reasons": list(promotion_block_receipt.get("block_reasons", [])),
            "allowed_next_move": str(promotion_block_receipt.get("allowed_next_move", "")).strip(),
        },
        "english_closeout_brief": english_brief,
        "what_track03_can_safely_claim_now": [
            "The Track 03 handoff bundle was materially real at intake and matched its declared hashes.",
            "Track 03 detected a real materialization defect and repaired it lawfully without silent overwrite.",
            "Track 03 refreshed current-head execution truth instead of counting against stale branch state.",
            "Track 03 passed targeted validation, smoke-before-counted discipline, deterministic bundle reproduction, and one counted H1 lane.",
            "Track 03 froze a proof bundle, signature surface, receipts, and a promotion block receipt in tracked staging.",
        ],
        "what_track03_still_cannot_safely_claim": [
            "Canonical promotion has happened.",
            "Broad KT theorem closure is fully proven by Track 03 alone.",
            "Router or lobe superiority is fully ratified.",
            "Commercial truth or broad platform readiness is solved.",
            "One counted H1 lane equals broad runtime or model superiority.",
        ],
        "source_refs": common.output_ref_dict(
            track02_final_summary_packet=common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_final_summary_packet.json"),
            track02_final_summary_receipt=common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_final_summary_receipt.json"),
            bundle_intake_receipt=common.resolve_path(root, f"KT_PROD_CLEANROOM/runs/post_f_track_03/{DEFAULT_RUN_ID}/artifacts/bundle_intake_receipt.json"),
            repo_safety_snapshot=common.resolve_path(root, f"KT_PROD_CLEANROOM/runs/post_f_track_03/{DEFAULT_RUN_ID}/artifacts/repo_safety_snapshot.json"),
            materialization_receipt=common.resolve_path(root, f"KT_PROD_CLEANROOM/runs/post_f_track_03/{DEFAULT_RUN_ID}/artifacts/materialization_receipt.json"),
            reconciliation_packet=common.resolve_path(root, f"KT_PROD_CLEANROOM/runs/post_f_track_03/{DEFAULT_RUN_ID}/artifacts/reconciliation_packet.json"),
            validation_matrix=common.resolve_path(root, f"KT_PROD_CLEANROOM/runs/post_f_track_03/{DEFAULT_RUN_ID}/artifacts/validation_matrix.json"),
            smoke_path_receipt=common.resolve_path(root, f"KT_PROD_CLEANROOM/runs/post_f_track_03/{DEFAULT_RUN_ID}/artifacts/smoke_path_receipt.json"),
            counted_path_receipt=common.resolve_path(root, f"KT_PROD_CLEANROOM/runs/post_f_track_03/{DEFAULT_RUN_ID}/artifacts/counted_path_receipt.json"),
            promotion_block_receipt=common.resolve_path(root, f"KT_PROD_CLEANROOM/runs/post_f_track_03/{DEFAULT_RUN_ID}/artifacts/promotion_block_receipt.json"),
            current_head_receipt=common.resolve_path(root, f"KT_PROD_CLEANROOM/runs/post_f_track_03/{DEFAULT_RUN_ID}/staging/reports/cohort0_current_head_receipt.json"),
            proof_bundle=proof_bundle_path,
            quarantine_note=quarantine_note_path,
        ),
        "subject_head": execution_head,
        "next_lawful_move": NEXT_MOVE,
    }

    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_track_03_final_summary_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "summary_outcome": SUMMARY_OUTCOME,
        "track_id": TRACK_ID,
        "subject_head": execution_head,
        "working_branch": branch_name,
        "working_branch_head_at_summary_time": branch_head,
        "working_branch_non_authoritative_until_protected_merge": True,
        "materialization_failed_honestly_then_repaired": True,
        "counted_path_completed": True,
        "promotion_block_preserved": True,
        "next_lawful_move": NEXT_MOVE,
    }

    report = common.report_lines(
        "Cohort0 Post-F Track 03 Final Summary Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Summary outcome: `{SUMMARY_OUTCOME}`",
            f"- Working branch: `{branch_name}`",
            f"- Execution head bound in current-head receipt: `{execution_head}`",
            f"- E02 materialization status: `{materialization_receipt.get('status', '')}`",
            f"- Reconciliation status: `{reconciliation_packet.get('status', '')}`",
            f"- Validation status: `{validation_matrix.get('status', '')}`",
            f"- Counted path status: `{counted_receipt.get('status', '')}`",
            f"- Proof bundle sha256: `{bundle_sha}`",
            f"- Promotion status: `{promotion_block_receipt.get('status', '')}`",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    track02_packet_path: Path,
    track02_receipt_path: Path,
    run_root: Path,
    quarantine_note_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_WORKING_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: Track 03 final summary must run on {REQUIRED_WORKING_BRANCH}, got {branch_name}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: Track 03 final summary requires a clean worktree before execution")

    track02_packet = common.load_json_required(root, track02_packet_path, label="Track 02 final summary packet")
    track02_receipt = common.load_json_required(root, track02_receipt_path, label="Track 02 final summary receipt")
    intake_receipt = common.load_json_required(root, run_root / "artifacts" / "bundle_intake_receipt.json", label="Track 03 bundle intake receipt")
    repo_snapshot = common.load_json_required(root, run_root / "artifacts" / "repo_safety_snapshot.json", label="Track 03 repo safety snapshot")
    materialization_receipt = common.load_json_required(root, run_root / "artifacts" / "materialization_receipt.json", label="Track 03 materialization receipt")
    reconciliation_packet = common.load_json_required(root, run_root / "artifacts" / "reconciliation_packet.json", label="Track 03 reconciliation packet")
    validation_matrix = common.load_json_required(root, run_root / "artifacts" / "validation_matrix.json", label="Track 03 validation matrix")
    smoke_receipt = common.load_json_required(root, run_root / "artifacts" / "smoke_path_receipt.json", label="Track 03 smoke receipt")
    counted_receipt = common.load_json_required(root, run_root / "artifacts" / "counted_path_receipt.json", label="Track 03 counted receipt")
    promotion_block_receipt = common.load_json_required(root, run_root / "artifacts" / "promotion_block_receipt.json", label="Track 03 promotion block receipt")
    current_head_receipt = common.load_json_required(root, run_root / "staging" / "reports" / "cohort0_current_head_receipt.json", label="Track 03 current-head receipt")
    counted_runtime_receipt = common.load_json_required(root, run_root / "staging" / "work" / "counted" / "current" / "receipt.json", label="Track 03 counted runtime receipt")
    quarantine_note = common.load_json_required(root, quarantine_note_path, label="Track 03 quarantine note")

    common.ensure_pass(track02_packet, label="Track 02 final summary packet")
    common.ensure_pass(track02_receipt, label="Track 02 final summary receipt")
    _require_status(intake_receipt, label="Track 03 bundle intake receipt", expected="PASS")
    _require_status(repo_snapshot, label="Track 03 repo safety snapshot", expected="PASS")
    _require_status(materialization_receipt, label="Track 03 materialization receipt", expected="FAIL")
    _require_status(reconciliation_packet, label="Track 03 reconciliation packet", expected="PASS_READY_FOR_VALIDATION")
    _require_status(validation_matrix, label="Track 03 validation matrix", expected="PASS")
    _require_status(smoke_receipt, label="Track 03 smoke receipt", expected="PASS")
    _require_status(counted_receipt, label="Track 03 counted receipt", expected="PASS")
    _require_status(promotion_block_receipt, label="Track 03 promotion block receipt", expected="BLOCKED")

    if str(track02_receipt.get("next_lawful_move", "")).strip() != "AUTHOR_POST_F_TRACK_03_SCOPE_PACKET":
        raise RuntimeError("FAIL_CLOSED: Track 02 closeout does not authorize Track 03 as the next stage")
    if not bool(track02_receipt.get("working_branch_non_authoritative_until_protected_merge", False)):
        raise RuntimeError("FAIL_CLOSED: Track 03 summary requires non-authoritative branch status preserved")
    if not materialization_receipt.get("mismatched_files"):
        raise RuntimeError("FAIL_CLOSED: Track 03 materialization fail must preserve the defect trail")
    checks = {str(row.get("name", "")).strip(): row for row in validation_matrix.get("checks", []) if isinstance(row, dict)}
    required_check_names = {"schema_examples_validate", "schema_digest_matches_manifest", "focused_pytest_stack", "smoke_path", "bundle_reproducibility", "counted_path"}
    missing = required_check_names.difference(checks)
    if missing:
        raise RuntimeError(f"FAIL_CLOSED: Track 03 validation matrix missing checks: {sorted(missing)}")
    if str(current_head_receipt.get("current_branch", "")).strip() != branch_name:
        raise RuntimeError("FAIL_CLOSED: Track 03 current-head receipt branch does not match current branch")
    if not bool(promotion_block_receipt.get("multisig_threshold_satisfied", False)):
        raise RuntimeError("FAIL_CLOSED: Track 03 promotion block must preserve satisfied multisig threshold")

    proof_bundle_path = common.resolve_path(root, run_root / "staging" / "bundle" / f"proof_bundle_{DEFAULT_RUN_ID}.tar.gz")
    proof_bundle_sha_path = common.resolve_path(root, run_root / "staging" / "bundle" / f"proof_bundle_{DEFAULT_RUN_ID}.tar.gz.sha256")
    proof_signature_path = common.resolve_path(root, run_root / "staging" / "signatures" / f"proof_bundle_{DEFAULT_RUN_ID}.sig")
    for path, label in (
        (proof_bundle_path, "Track 03 proof bundle"),
        (proof_bundle_sha_path, "Track 03 proof bundle sha file"),
        (proof_signature_path, "Track 03 proof signature"),
    ):
        if not path.is_file():
            raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")

    outputs = build_outputs(
        root=root,
        branch_name=branch_name,
        branch_head=_current_head(root),
        track02_packet=track02_packet,
        track02_receipt=track02_receipt,
        intake_receipt=intake_receipt,
        repo_snapshot=repo_snapshot,
        materialization_receipt=materialization_receipt,
        reconciliation_packet=reconciliation_packet,
        validation_matrix=validation_matrix,
        smoke_receipt=smoke_receipt,
        counted_receipt=counted_receipt,
        promotion_block_receipt=promotion_block_receipt,
        current_head_receipt=current_head_receipt,
        counted_runtime_receipt=counted_runtime_receipt,
        proof_bundle_path=proof_bundle_path,
        proof_bundle_sha_path=proof_bundle_sha_path,
        proof_signature_path=proof_signature_path,
        quarantine_note_path=common.resolve_path(root, quarantine_note_path),
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
        "summary_outcome": SUMMARY_OUTCOME,
        "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(),
        "next_lawful_move": NEXT_MOVE,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Author the Track 03 final summary packet.")
    parser.add_argument(
        "--track02-packet",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_final_summary_packet.json",
    )
    parser.add_argument(
        "--track02-receipt",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_final_summary_receipt.json",
    )
    parser.add_argument(
        "--run-root",
        default=f"KT_PROD_CLEANROOM/runs/post_f_track_03/{DEFAULT_RUN_ID}",
    )
    parser.add_argument(
        "--quarantine-note",
        default=f"reports/post_f_track_03_quarantine/{DEFAULT_RUN_ID}/bundle_manifest_row_task_summary_quarantine.json",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        track02_packet_path=common.resolve_path(root, args.track02_packet),
        track02_receipt_path=common.resolve_path(root, args.track02_receipt),
        run_root=common.resolve_path(root, args.run_root),
        quarantine_note_path=common.resolve_path(root, args.quarantine_note),
    )
    print(result["summary_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
