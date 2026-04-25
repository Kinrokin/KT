from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_post_f_track_03_final_summary_packet_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_track_03_final_summary_freezes_execution_closeout(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    run_root = tmp_path / "KT_PROD_CLEANROOM" / "runs" / "post_f_track_03" / tranche.DEFAULT_RUN_ID
    quarantine_note = tmp_path / "reports" / "post_f_track_03_quarantine" / tranche.DEFAULT_RUN_ID / "bundle_manifest_row_task_summary_quarantine.json"

    _write_json(
        reports / "cohort0_post_f_track_02_final_summary_packet.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_02_final_summary_packet.v1",
            "status": "PASS",
            "authority_header": {
                "canonical_authority_branch": "main",
                "working_branch": tranche.REQUIRED_WORKING_BRANCH,
                "working_branch_non_authoritative_until_protected_merge": True,
                "gate_d_cleared_on_successor_line": True,
                "gate_e_open_on_successor_line": True,
                "gate_f_narrow_wedge_confirmed": True,
                "gate_f_open": False,
                "post_f_reaudit_passed": True,
            },
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_02_final_summary_receipt.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_02_final_summary_receipt.v1",
            "status": "PASS",
            "summary_outcome": "POST_F_TRACK_02_DUAL_AUDIT_FROZEN__ENGLISH_EXECUTIVE_BRIEF_BOUND",
            "subject_head": "track02-sha",
            "next_lawful_move": "AUTHOR_POST_F_TRACK_03_SCOPE_PACKET",
            "working_branch_non_authoritative_until_protected_merge": True,
        },
    )
    _write_json(run_root / "artifacts" / "bundle_intake_receipt.json", {"status": "PASS"})
    _write_json(run_root / "artifacts" / "repo_safety_snapshot.json", {"status": "PASS"})
    _write_json(
        run_root / "artifacts" / "materialization_receipt.json",
        {
            "status": "FAIL",
            "mismatched_files": [
                {
                    "path": "staging/task_summary.json",
                    "expected_sha256": "bad",
                    "observed_sha256": "good",
                }
            ],
        },
    )
    _write_json(
        run_root / "artifacts" / "reconciliation_packet.json",
        {
            "status": "PASS_READY_FOR_VALIDATION",
            "hardening_changes": ["change-a"],
            "superseded": [{"path": "staging/task_summary.json"}],
        },
    )
    _write_json(
        run_root / "artifacts" / "validation_matrix.json",
        {
            "status": "PASS",
            "counted_path_rule": "PASS: exactly one counted receipt exists",
            "checks": [
                {"name": "schema_examples_validate", "status": "PASS"},
                {"name": "schema_digest_matches_manifest", "status": "PASS"},
                {"name": "focused_pytest_stack", "status": "PASS"},
                {"name": "smoke_path", "status": "PASS"},
                {"name": "bundle_reproducibility", "status": "PASS"},
                {"name": "counted_path", "status": "PASS"},
            ],
        },
    )
    _write_json(run_root / "artifacts" / "smoke_path_receipt.json", {"status": "PASS"})
    _write_json(
        run_root / "artifacts" / "counted_path_receipt.json",
        {
            "status": "PASS",
            "manifest_digest": "manifest-123",
        },
    )
    _write_json(
        run_root / "artifacts" / "promotion_block_receipt.json",
        {
            "status": "BLOCKED",
            "multisig_threshold_satisfied": True,
            "promotion_attempted": False,
            "block_reasons": ["branch non-authoritative"],
            "allowed_next_move": "human review",
        },
    )
    _write_json(
        run_root / "staging" / "reports" / "cohort0_current_head_receipt.json",
        {
            "status": "PASS",
            "current_git_head": "track03-exec-sha",
            "current_branch": tranche.REQUIRED_WORKING_BRANCH,
        },
    )
    _write_json(
        run_root / "staging" / "work" / "counted" / "current" / "receipt.json",
        {
            "provider_calls": [
                {"provider": "openai_hashed", "prompt_sha256": "a" * 64, "response_sha256": "b" * 64, "receipt_id": "prov-1"},
                {"provider": "mock_local", "prompt_sha256": "c" * 64, "response_sha256": "d" * 64, "receipt_id": "prov-2"},
            ],
            "results": [
                {"decision_label": "commit", "why_not": ["WN001_NO_POLICY_MATCH"]},
                {"decision_label": "defer", "why_not": ["WN002_LOW_MARGIN"]},
            ],
        },
    )
    bundle_path = run_root / "staging" / "bundle" / f"proof_bundle_{tranche.DEFAULT_RUN_ID}.tar.gz"
    bundle_bytes = b"bundle-bytes"
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    bundle_path.write_bytes(bundle_bytes)
    bundle_sha = __import__("hashlib").sha256(bundle_bytes).hexdigest()
    _write_text(run_root / "staging" / "bundle" / f"proof_bundle_{tranche.DEFAULT_RUN_ID}.tar.gz.sha256", f"{bundle_sha}  proof_bundle.tar.gz\n")
    _write_text(run_root / "staging" / "signatures" / f"proof_bundle_{tranche.DEFAULT_RUN_ID}.sig", "sig")
    _write_json(quarantine_note, {"status": "QUARANTINED", "path": "staging/task_summary.json"})

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_WORKING_BRANCH)
    monkeypatch.setattr(tranche, "_current_head", lambda root: "summary-head-sha")
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")

    result = tranche.run(
        reports_root=reports,
        track02_packet_path=reports / "cohort0_post_f_track_02_final_summary_packet.json",
        track02_receipt_path=reports / "cohort0_post_f_track_02_final_summary_receipt.json",
        run_root=run_root,
        quarantine_note_path=quarantine_note,
    )

    assert result["summary_outcome"] == tranche.SUMMARY_OUTCOME

    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)

    assert packet["phase_summary"]["E02_materialization"] == "FAIL"
    assert packet["defect_and_repair_summary"]["materialization_failed_honestly"] is True
    assert packet["promotion_boundary"]["promotion_blocked"] is True
    assert packet["execution_closeout"]["counted_decision_summary"]["commit_count"] == 1
    assert packet["next_lawful_move"] == tranche.NEXT_MOVE
    assert receipt["materialization_failed_honestly_then_repaired"] is True
    assert receipt["promotion_block_preserved"] is True
