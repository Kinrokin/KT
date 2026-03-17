from __future__ import annotations

import json
import subprocess
from pathlib import Path

from tools.operator.authority_convergence_closeout import (
    build_authority_closure_receipt,
    build_kt_published_head_self_convergence_receipt,
    build_sovereign_authority_and_published_head_closure_receipt,
    build_sovereign_blocker_matrix,
    build_sovereign_current_head_truth_source,
)


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_call(root: Path, *args: str) -> None:
    subprocess.check_call(["git", "-C", str(root), *args])


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _init_repo(tmp_path: Path) -> None:
    _git_call(tmp_path, "init", "-b", "main")
    _git_call(tmp_path, "config", "user.email", "test@example.com")
    _git_call(tmp_path, "config", "user.name", "Test User")
    (tmp_path / "README.md").write_text("base\n", encoding="utf-8")
    _git_call(tmp_path, "add", "README.md")
    _git_call(tmp_path, "commit", "-m", "base")


def test_authority_closeout_wraps_legacy_pass_receipts_with_no_unexpected_touches(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"

    _write_json(
        reports / "authority_convergence_receipt.json",
        {
            "schema_id": "kt.operator.authority_convergence_receipt.v2",
            "status": "PASS",
            "proof_class": "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN",
            "published_head_authority_claimed": True,
            "current_head_authority_claimed": True,
            "h1_admissible": False,
            "failures": [],
            "observed": {
                "truth_subject_commit": head,
                "evidence_commit": head,
                "current_head_commit": head,
                "ledger_branch_published": True,
                "ledger_branch_head_sha": head,
                "ledger_pointer_head": head,
                "ledger_current_state_head": head,
                "ledger_runtime_audit_head": head,
            },
        },
    )
    _write_json(
        reports / "published_head_self_convergence_receipt.json",
        {
            "schema_id": "kt.operator.published_head_self_convergence_receipt.v2",
            "status": "PASS",
            "proof_class": "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN",
            "validated_head_sha": head,
            "truth_subject_commit": head,
            "evidence_commit": head,
            "current_head_commit": head,
            "head_equals_subject": True,
            "current_head_claim_verdict": "HEAD_IS_TRANSPARENCY_VERIFIED_SUBJECT",
            "published_head_authority_claimed": True,
            "current_head_authority_claimed": True,
            "ledger_branch_published": True,
            "ledger_branch_head_sha": head,
            "main_live_truth_purged": True,
            "blockers": [],
        },
    )
    _write_json(
        reports / "reporting_integrity_repair_receipt.json",
        {
            "schema_id": "kt.operator.reporting_integrity_repair_receipt.v2",
            "status": "PASS",
        },
    )

    kt_published = build_kt_published_head_self_convergence_receipt(root=tmp_path)
    _write_json(reports / "kt_published_head_self_convergence_receipt.json", kt_published)
    _git_call(tmp_path, "add", ".")
    _git_call(tmp_path, "commit", "-m", "seed ws9 receipts")
    closure = build_authority_closure_receipt(root=tmp_path, generated_utc="2026-03-15T00:00:00Z")

    assert kt_published["status"] == "PASS"
    assert kt_published["pass_verdict"] == "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN"
    assert closure["status"] == "PASS", closure
    assert closure["pass_verdict"] == "AUTHORITY_AND_PUBLISHED_HEAD_CLOSED"
    assert closure["unexpected_touches"] == []
    assert closure["protected_touch_violations"] == []


def test_sovereign_ws9_receipt_narrows_current_head_to_evidence_only() -> None:
    authority = {
        "schema_id": "kt.operator.authority_convergence_receipt.v2",
        "status": "PASS",
        "proof_class": "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN",
        "observed": {
            "truth_subject_commit": "b" * 40,
            "verifier_evidence_commit": "a" * 40,
            "verifier_head_claim_verdict": "HEAD_CONTAINS_TRANSPARENCY_VERIFIED_SUBJECT_EVIDENCE",
        },
    }
    published = {
        "schema_id": "kt.operator.published_head_self_convergence_receipt.v2",
        "status": "PASS",
        "proof_class": "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN",
        "truth_subject_commit": "b" * 40,
        "evidence_commit": "a" * 40,
        "head_equals_subject": False,
        "published_head_authority_claimed": True,
        "current_head_authority_claimed": False,
        "current_head_claim_verdict": "HEAD_CONTAINS_TRANSPARENCY_VERIFIED_SUBJECT_EVIDENCE",
    }
    reporting = {"schema_id": "kt.operator.reporting_integrity_receipt.v2", "status": "PASS"}
    truth_source = build_sovereign_current_head_truth_source(
        current_repo_head="c" * 40,
        authority_report=authority,
        published_report=published,
    )
    blocker_matrix = build_sovereign_blocker_matrix(
        current_repo_head="c" * 40,
        authority_report=authority,
        published_report=published,
        h1_receipt={"status": "BLOCKED"},
        stabilization_receipt={"status": "PASS", "truth_publication_stabilized": True},
        verifier_manifest={"platform_governance_claim_admissible": False},
        platform_receipt={"platform_governance_claim_admissible": False},
        representative_receipt={"cross_environment_controlled_variation_complete": False, "validated_head_sha": "old"},
        two_clean_clone_receipt={"cross_environment_controlled_variation_complete": False, "validated_head_sha": "old"},
    )
    receipt = build_sovereign_authority_and_published_head_closure_receipt(
        current_repo_head="c" * 40,
        authority_report=authority,
        published_report=published,
        reporting_integrity_receipt=reporting,
        blocker_matrix=blocker_matrix,
        files_touched=["KT_PROD_CLEANROOM/tools/operator/authority_convergence_closeout.py"],
    )

    assert truth_source["current_head_authority_claimed"] is False
    assert truth_source["published_head_authority_claimed"] is True
    assert receipt["status"] == "PASS"
    assert receipt["pass_verdict"] == "AUTHORITY_AND_PUBLISHED_HEAD_RECONCILED_WITH_CURRENT_HEAD_NARROWING"
    assert "H1_ACTIVATION_GATE_CLOSED" in receipt["blocked_by"]
    assert "PLATFORM_ENFORCEMENT_UNPROVEN" in receipt["blocked_by"]
    assert "CURRENT_HEAD_IS_TRANSPARENCY_VERIFIED_SUBJECT" in receipt["forbidden_claims"]
    rows = {row["blocker_id"]: row["status"] for row in blocker_matrix["rows"]}
    assert rows["AUTHORITY_CONVERGENCE_UNRESOLVED"] == "RESOLVED_WITH_CURRENT_HEAD_NARROWING"
    assert rows["PUBLISHED_HEAD_SELF_CONVERGENCE_UNRESOLVED"] == "RESOLVED_WITH_CURRENT_HEAD_NARROWING"
    assert rows["TRUTH_PUBLICATION_STABILIZED_FALSE"] == "RESOLVED"
    assert rows["CROSS_ENV_CONTROLLED_VARIATION_NOT_RUN_OR_NOT_CURRENT"] == "OPEN"


def test_sovereign_ws9_receipt_blocks_when_authority_lane_fails() -> None:
    authority = {
        "schema_id": "kt.operator.authority_convergence_receipt.v2",
        "status": "FAIL",
        "proof_class": "FAIL_CLOSED",
        "observed": {
            "truth_subject_commit": "b" * 40,
            "verifier_evidence_commit": "a" * 40,
            "verifier_head_claim_verdict": "HEAD_TRANSPARENCY_CLAIM_UNPROVEN",
        },
    }
    published = {
        "schema_id": "kt.operator.published_head_self_convergence_receipt.v2",
        "status": "FAIL_CLOSED",
        "proof_class": "FAIL_CLOSED",
        "truth_subject_commit": "b" * 40,
        "evidence_commit": "a" * 40,
        "head_equals_subject": False,
        "published_head_authority_claimed": False,
        "current_head_authority_claimed": False,
        "current_head_claim_verdict": "HEAD_TRANSPARENCY_CLAIM_UNPROVEN",
    }
    reporting = {"schema_id": "kt.operator.reporting_integrity_receipt.v2", "status": "FAIL_CLOSED"}
    blocker_matrix = build_sovereign_blocker_matrix(
        current_repo_head="c" * 40,
        authority_report=authority,
        published_report=published,
        h1_receipt={"status": "BLOCKED"},
        stabilization_receipt={"status": "FAIL", "truth_publication_stabilized": False},
        verifier_manifest={"platform_governance_claim_admissible": False},
        platform_receipt={"platform_governance_claim_admissible": False},
        representative_receipt={"cross_environment_controlled_variation_complete": False, "validated_head_sha": "old"},
        two_clean_clone_receipt={"cross_environment_controlled_variation_complete": False, "validated_head_sha": "old"},
    )
    receipt = build_sovereign_authority_and_published_head_closure_receipt(
        current_repo_head="c" * 40,
        authority_report=authority,
        published_report=published,
        reporting_integrity_receipt=reporting,
        blocker_matrix=blocker_matrix,
        files_touched=["KT_PROD_CLEANROOM/tools/operator/authority_convergence_closeout.py"],
    )

    assert receipt["status"] == "BLOCKED"
    assert receipt["pass_verdict"] == "FAIL_CLOSED"
