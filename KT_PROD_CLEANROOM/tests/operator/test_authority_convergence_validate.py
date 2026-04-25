from __future__ import annotations

import json
import subprocess
from pathlib import Path

from tools.operator.authority_convergence_validate import build_authority_convergence_report
from tools.operator.public_verifier import SUBJECT_VERDICT_PROVEN


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_call(root: Path, *args: str) -> None:
    subprocess.check_call(["git", "-C", str(root), *args])


def _init_repo_with_remote(tmp_path: Path) -> None:
    _git_call(tmp_path, "init", "-b", "main")
    _git_call(tmp_path, "config", "user.email", "test@example.com")
    _git_call(tmp_path, "config", "user.name", "Test User")
    (tmp_path / "README.md").write_text("x\n", encoding="utf-8")
    _git_call(tmp_path, "add", "README.md")
    _git_call(tmp_path, "commit", "-m", "init")

    remote = (tmp_path / "remote.git").resolve()
    subprocess.check_call(["git", "init", "--bare", str(remote)])
    _git_call(tmp_path, "remote", "add", "origin", str(remote))


def _seed_ws9_surfaces(tmp_path: Path, *, truth_subject: str, evidence_commit: str) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    gov = tmp_path / "KT_PROD_CLEANROOM" / "governance"
    main_truth = tmp_path / "KT_PROD_CLEANROOM" / "exports" / "_truth" / "current"
    ledger = tmp_path / "ledger" / "current"

    _write_json(
        gov / "documentary_truth_policy.json",
        {
            "schema_id": "kt.governance.documentary_truth_policy.v1",
            "active_current_head_truth_source": "kt_truth_ledger:ledger/current/current_pointer.json",
            "active_supporting_truth_surfaces": [
                "kt_truth_ledger:ledger/current/current_state_receipt.json",
                "kt_truth_ledger:ledger/current/runtime_closure_audit.json",
            ],
            "documentary_only_refs": [
                "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
                "KT_PROD_CLEANROOM/reports/current_state_receipt.json",
                "KT_PROD_CLEANROOM/reports/runtime_closure_audit.json",
            ],
        },
    )
    _write_json(
        gov / "execution_board.json",
        {
            "schema_id": "kt.governance.execution_board.v3",
            "authoritative_current_head_truth_source": "kt_truth_ledger:ledger/current/current_pointer.json",
            "authority_mode": "SETTLED_AUTHORITATIVE",
        },
    )
    _write_json(
        gov / "readiness_scope_manifest.json",
        {
            "schema_id": "kt.governance.readiness_scope_manifest.v2",
            "authoritative_truth_source": "kt_truth_ledger:ledger/current/current_pointer.json",
        },
    )

    _write_json(
        reports / "main_branch_protection_receipt.json",
        {
            "schema_id": "kt.main_branch_protection_receipt.v2",
            "status": "BLOCKED",
            "claim_admissible": False,
            "validated_head_sha": truth_subject,
            "platform_block": {"http_status": 403, "message": "blocked"},
        },
    )
    _write_json(
        reports / "ci_gate_promotion_receipt.json",
        {
            "schema_id": "kt.sovereign.ci_gate_promotion_receipt.v1",
            "status": "PASS_WITH_PLATFORM_BLOCK",
            "head_sha": truth_subject,
        },
    )
    _write_json(
        reports / "cryptographic_publication_receipt.json",
        {"schema_id": "kt.operator.cryptographic_publication_receipt.v1", "status": "PASS"},
    )
    _write_json(
        reports / "cryptographic_publication" / "authority_subject.json",
        {
            "schema_id": "kt.authority.subject.v1",
            "truth_subject_commit": truth_subject,
            "truth_produced_at_commit": truth_subject,
        },
    )
    _write_json(
        reports / "kt_truth_publication_stabilization_receipt.json",
        {
            "schema_id": "kt.operator.truth_publication_stabilization_receipt.v2",
            "status": "PASS",
            "truth_publication_stabilized": True,
            "truth_subject_commit": truth_subject,
        },
    )
    _write_json(
        reports / "truth_publication_stabilization_receipt.json",
        {
            "schema_id": "kt.operator.truth_publication_stabilization_receipt.v1",
            "status": "PASS",
            "authority_mode": "SETTLED_AUTHORITATIVE",
            "posture_state": "TRUTHFUL_GREEN",
            "board_transition_ready": True,
            "truth_subject_commit": truth_subject,
            "truth_produced_at_commit": truth_subject,
        },
    )
    _write_json(reports / "documentary_truth_validation_receipt.json", {"schema_id": "kt.operator.documentary_truth_validation_receipt.v1", "status": "PASS"})
    _write_json(
        reports / "public_verifier_manifest.json",
        {
            "schema_id": "kt.public_verifier_manifest.v4",
            "status": "HOLD",
            "evidence_commit": evidence_commit,
            "truth_subject_commit": truth_subject,
            "subject_verdict": SUBJECT_VERDICT_PROVEN,
            "publication_receipt_status": "PASS",
            "evidence_contains_subject": True,
            "evidence_equals_subject": False,
            "claim_boundary": "evidence and subject are distinct",
            "platform_governance_subject_commit": truth_subject,
            "platform_governance_verdict": "WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED",
            "platform_governance_claim_admissible": False,
            "workflow_governance_status": "PASS_WITH_PLATFORM_BLOCK",
            "branch_protection_status": "BLOCKED",
            "platform_governance_claim_boundary": "workflow governance only",
            "enterprise_legitimacy_ceiling": "WORKFLOW_GOVERNANCE_ONLY",
            "platform_governance_receipt_refs": [
                "KT_PROD_CLEANROOM/reports/ci_gate_promotion_receipt.json",
                "KT_PROD_CLEANROOM/reports/main_branch_protection_receipt.json",
            ],
            "publication_evidence_refs": [
                "KT_PROD_CLEANROOM/reports/cryptographic_publication_receipt.json",
                "KT_PROD_CLEANROOM/reports/cryptographic_publication/authority_subject.json",
            ],
        },
    )

    _write_json(
        ledger / "current_pointer.json",
        {
            "schema_id": "kt.operator.truth_pointer.v1",
            "truth_subject_commit": truth_subject,
            "posture_enum": "TRUTHFUL_GREEN",
        },
    )
    _write_json(
        ledger / "current_state_receipt.json",
        {
            "schema_id": "kt.operator.current_state_receipt.v4",
            "validated_head_sha": truth_subject,
            "branch_ref": "main",
            "posture_state": "TRUTHFUL_GREEN",
        },
    )
    _write_json(
        ledger / "runtime_closure_audit.json",
        {
            "schema_id": "kt.operator.runtime_closure_audit.v4",
            "validated_head_sha": truth_subject,
            "branch_ref": "main",
            "posture_state": "TRUTHFUL_GREEN",
        },
    )

    _write_json(
        main_truth / "current_pointer.json",
        {
            "schema_id": "kt.operator.truth_pointer.v1",
            "truth_subject_commit": truth_subject,
            "status": "SUPERSEDED_DOCUMENTARY_ONLY",
            "documentary_only": True,
            "live_authority": False,
        },
    )
    _write_json(
        reports / "current_state_receipt.json",
        {
            "schema_id": "kt.operator.current_state_receipt.v3",
            "validated_head_sha": truth_subject,
            "status": "PASS",
            "posture_state": "TRUTHFUL_GREEN",
            "documentary_only": True,
            "live_authority": False,
        },
    )
    _write_json(
        reports / "runtime_closure_audit.json",
        {
            "schema_id": "kt.operator.runtime_closure_audit.v3",
            "validated_head_sha": truth_subject,
            "status": "PASS",
            "posture_state": "TRUTHFUL_GREEN",
            "documentary_only": True,
            "live_authority": False,
        },
    )


def test_authority_convergence_passes_when_published_subject_and_ledger_surfaces_align(tmp_path: Path) -> None:
    _init_repo_with_remote(tmp_path)
    _seed_ws9_surfaces(tmp_path, truth_subject="b" * 40, evidence_commit="a" * 40)
    _git_call(tmp_path, "add", ".")
    _git_call(tmp_path, "commit", "-m", "seed ws9")
    _git_call(tmp_path, "push", "-u", "origin", "main")
    _git_call(tmp_path, "push", "origin", "HEAD:refs/heads/kt_truth_ledger")
    _git_call(tmp_path, "fetch", "origin", "kt_truth_ledger")
    report = build_authority_convergence_report(root=tmp_path)
    assert report["status"] == "PASS", report
    assert report["proof_class"] == "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN"
    assert report["h1_admissible"] is False


def test_authority_convergence_fails_when_ledger_pointer_disagrees_with_published_subject(tmp_path: Path) -> None:
    _init_repo_with_remote(tmp_path)
    _seed_ws9_surfaces(tmp_path, truth_subject="b" * 40, evidence_commit="a" * 40)
    _git_call(tmp_path, "add", ".")
    _git_call(tmp_path, "commit", "-m", "seed ws9")
    _git_call(tmp_path, "push", "-u", "origin", "main")
    _git_call(tmp_path, "push", "origin", "HEAD:refs/heads/kt_truth_ledger")
    _git_call(tmp_path, "fetch", "origin", "kt_truth_ledger")
    _git_call(tmp_path, "checkout", "-b", "kt_truth_ledger")
    _write_json(
        tmp_path / "ledger" / "current" / "current_pointer.json",
        {
            "schema_id": "kt.operator.truth_pointer.v1",
            "truth_subject_commit": "c" * 40,
            "posture_enum": "TRUTHFUL_GREEN",
        },
    )
    _git_call(tmp_path, "add", "ledger/current/current_pointer.json")
    _git_call(tmp_path, "commit", "-m", "break ledger pointer")
    _git_call(tmp_path, "checkout", "main")
    report = build_authority_convergence_report(root=tmp_path)
    assert report["status"] == "FAIL"
    assert "tracked_publication_stabilization_subject_matches_active_truth" in report["failures"]
    assert "tracked_publication_stabilization_supports_active_truth" in report["failures"]
    assert "ledger_current_state_matches_truth_subject" in report["failures"]
    assert "ledger_runtime_audit_matches_truth_subject" in report["failures"]


def test_authority_convergence_fails_when_current_head_boundary_is_overread(tmp_path: Path) -> None:
    _init_repo_with_remote(tmp_path)
    _seed_ws9_surfaces(tmp_path, truth_subject="b" * 40, evidence_commit="a" * 40)
    _git_call(tmp_path, "add", ".")
    _git_call(tmp_path, "commit", "-m", "seed ws9")
    _git_call(tmp_path, "push", "-u", "origin", "main")
    _git_call(tmp_path, "push", "origin", "HEAD:refs/heads/kt_truth_ledger")
    _git_call(tmp_path, "fetch", "origin", "kt_truth_ledger")
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "public_verifier_manifest.json",
        {
            "schema_id": "kt.public_verifier_manifest.v4",
            "status": "HOLD",
            "evidence_commit": "a" * 40,
            "truth_subject_commit": "b" * 40,
            "subject_verdict": SUBJECT_VERDICT_PROVEN,
            "publication_receipt_status": "PASS",
            "evidence_contains_subject": False,
            "evidence_equals_subject": False,
            "claim_boundary": "broken boundary",
            "platform_governance_subject_commit": "b" * 40,
            "platform_governance_verdict": "WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED",
            "platform_governance_claim_admissible": False,
            "workflow_governance_status": "PASS_WITH_PLATFORM_BLOCK",
            "branch_protection_status": "BLOCKED",
            "platform_governance_claim_boundary": "workflow governance only",
            "enterprise_legitimacy_ceiling": "WORKFLOW_GOVERNANCE_ONLY",
            "platform_governance_receipt_refs": [
                "KT_PROD_CLEANROOM/reports/ci_gate_promotion_receipt.json",
                "KT_PROD_CLEANROOM/reports/main_branch_protection_receipt.json",
            ],
            "publication_evidence_refs": [
                "KT_PROD_CLEANROOM/reports/cryptographic_publication_receipt.json",
                "KT_PROD_CLEANROOM/reports/cryptographic_publication/authority_subject.json",
            ],
        },
    )
    report = build_authority_convergence_report(root=tmp_path)
    assert report["status"] == "FAIL"
    assert "current_head_claim_boundary_preserved" in report["failures"]


def test_authority_convergence_passes_with_local_ledger_proof_when_legacy_publication_subject_lags(tmp_path: Path) -> None:
    _init_repo_with_remote(tmp_path)
    _seed_ws9_surfaces(tmp_path, truth_subject="b" * 40, evidence_commit="a" * 40)
    _git_call(tmp_path, "add", ".")
    _git_call(tmp_path, "commit", "-m", "seed ws9")
    _git_call(tmp_path, "push", "-u", "origin", "main")
    _git_call(tmp_path, "push", "origin", "HEAD:refs/heads/kt_truth_ledger")
    _git_call(tmp_path, "fetch", "origin", "kt_truth_ledger")

    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cryptographic_publication" / "authority_subject.json",
        {
            "schema_id": "kt.authority.subject.v1",
            "truth_subject_commit": "c" * 40,
            "truth_produced_at_commit": "c" * 40,
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "kt_truth_publication_stabilization_receipt.json",
        {
            "schema_id": "kt.operator.truth_publication_stabilization_receipt.v2",
            "status": "PASS",
            "truth_publication_stabilized": True,
            "truth_subject_commit": "c" * 40,
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "public_verifier_manifest.json",
        {
            "schema_id": "kt.public_verifier_manifest.v4",
            "status": "HOLD",
            "evidence_commit": "a" * 40,
            "truth_subject_commit": "c" * 40,
            "subject_verdict": SUBJECT_VERDICT_PROVEN,
            "publication_receipt_status": "PASS",
            "evidence_contains_subject": True,
            "evidence_equals_subject": False,
            "claim_boundary": "evidence and subject are distinct",
            "platform_governance_subject_commit": "c" * 40,
            "platform_governance_verdict": "WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED",
            "platform_governance_claim_admissible": False,
            "workflow_governance_status": "PASS_WITH_PLATFORM_BLOCK",
            "branch_protection_status": "BLOCKED",
            "platform_governance_claim_boundary": "workflow governance only",
            "enterprise_legitimacy_ceiling": "WORKFLOW_GOVERNANCE_ONLY",
            "platform_governance_receipt_refs": [
                "KT_PROD_CLEANROOM/reports/ci_gate_promotion_receipt.json",
                "KT_PROD_CLEANROOM/reports/main_branch_protection_receipt.json",
            ],
            "publication_evidence_refs": [
                "KT_PROD_CLEANROOM/reports/cryptographic_publication_receipt.json",
                "KT_PROD_CLEANROOM/reports/cryptographic_publication/authority_subject.json",
            ],
        },
    )

    report = build_authority_convergence_report(root=tmp_path)
    assert report["status"] == "PASS"
    assert report["proof_class"] == "LOCAL_LEDGER_SELF_CONVERGENCE_ONLY"
    assert report["published_head_authority_claimed"] is False
    assert report["current_head_authority_claimed"] is False
    assert "ledger_pointer_matches_truth_subject" not in report["failures"]


def test_authority_convergence_passes_with_local_ledger_proof_when_tracked_stabilization_rebinds_current_head(tmp_path: Path) -> None:
    _init_repo_with_remote(tmp_path)
    _seed_ws9_surfaces(tmp_path, truth_subject="b" * 40, evidence_commit="a" * 40)
    _git_call(tmp_path, "add", ".")
    _git_call(tmp_path, "commit", "-m", "seed ws9")
    _git_call(tmp_path, "push", "-u", "origin", "main")
    _git_call(tmp_path, "push", "origin", "HEAD:refs/heads/kt_truth_ledger")
    _git_call(tmp_path, "fetch", "origin", "kt_truth_ledger")

    current_head = _git(tmp_path, "rev-parse", "HEAD")
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "settled_truth_source_receipt.json",
        {
            "schema_id": "kt.operator.settled_truth_source_receipt.v1",
            "status": "SETTLED_AUTHORITATIVE",
            "pinned_head_sha": current_head,
            "derived_posture_state": "CANONICAL_READY_FOR_REEARNED_GREEN",
            "current_head_truth_source": "KT_PROD_CLEANROOM/reports/live_validation_index.json",
            "head_relation": "HEAD_DIVERGED_FROM_ACTIVE_SUBJECT",
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cryptographic_publication" / "authority_subject.json",
        {
            "schema_id": "kt.authority.subject.v1",
            "truth_subject_commit": "c" * 40,
            "truth_produced_at_commit": "c" * 40,
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "kt_truth_publication_stabilization_receipt.json",
        {
            "schema_id": "kt.operator.truth_publication_stabilization_receipt.v2",
            "status": "PASS",
            "truth_publication_stabilized": True,
            "truth_subject_commit": "c" * 40,
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "public_verifier_manifest.json",
        {
            "schema_id": "kt.public_verifier_manifest.v4",
            "status": "HOLD",
            "evidence_commit": "a" * 40,
            "truth_subject_commit": "c" * 40,
            "subject_verdict": SUBJECT_VERDICT_PROVEN,
            "publication_receipt_status": "PASS",
            "evidence_contains_subject": True,
            "evidence_equals_subject": False,
            "claim_boundary": "evidence and subject are distinct",
            "platform_governance_subject_commit": "c" * 40,
            "platform_governance_verdict": "WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED",
            "platform_governance_claim_admissible": False,
            "workflow_governance_status": "PASS_WITH_PLATFORM_BLOCK",
            "branch_protection_status": "BLOCKED",
            "platform_governance_claim_boundary": "workflow governance only",
            "enterprise_legitimacy_ceiling": "WORKFLOW_GOVERNANCE_ONLY",
            "platform_governance_receipt_refs": [
                "KT_PROD_CLEANROOM/reports/ci_gate_promotion_receipt.json",
                "KT_PROD_CLEANROOM/reports/main_branch_protection_receipt.json",
            ],
            "publication_evidence_refs": [
                "KT_PROD_CLEANROOM/reports/cryptographic_publication_receipt.json",
                "KT_PROD_CLEANROOM/reports/cryptographic_publication/authority_subject.json",
            ],
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "truth_publication_stabilization_receipt.json",
        {
            "schema_id": "kt.operator.truth_publication_stabilization_receipt.v1",
            "status": "HOLD",
            "authority_mode": "SETTLED_AUTHORITATIVE",
            "posture_state": "CANONICAL_READY_FOR_REEARNED_GREEN",
            "board_transition_ready": False,
            "truth_subject_commit": current_head,
            "truth_produced_at_commit": current_head,
        },
    )

    report = build_authority_convergence_report(root=tmp_path)
    assert report["status"] == "PASS"
    assert report["proof_class"] == "LOCAL_LEDGER_SELF_CONVERGENCE_ONLY"
    assert report["published_head_authority_claimed"] is False
    assert report["current_head_authority_claimed"] is False
    checks = {row["check"]: row["status"] for row in report["checks"]}
    assert checks["tracked_publication_stabilization_subject_matches_active_truth"] == "WARN"
    assert checks["tracked_publication_stabilization_supports_active_truth"] == "WARN"
    assert checks["tracked_publication_stabilization_subject_matches_local_ledger_head"] == "PASS"
    assert checks["tracked_publication_stabilization_supports_local_ledger_head"] == "PASS"
    assert checks["settled_truth_source_pins_current_head_for_local_ledger_transition"] == "PASS"
