from __future__ import annotations

import json
import subprocess
from pathlib import Path

from tools.operator.reporting_integrity import repair_reporting_integrity, verify_reporting_integrity
from tools.operator.public_verifier import SUBJECT_VERDICT_PROVEN


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_call(root: Path, *args: str) -> None:
    subprocess.check_call(["git", "-C", str(root), *args])


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def _init_repo_with_remote(tmp_path: Path) -> None:
    _git_call(tmp_path, "init", "-b", "main")
    _git_call(tmp_path, "config", "user.email", "test@example.com")
    _git_call(tmp_path, "config", "user.name", "Test User")
    (tmp_path / "README.md").write_text("x\n", encoding="utf-8", newline="\n")
    _git_call(tmp_path, "add", "README.md")
    _git_call(tmp_path, "commit", "-m", "init")

    remote = (tmp_path / "remote.git").resolve()
    subprocess.check_call(["git", "init", "--bare", str(remote)])
    _git_call(tmp_path, "remote", "add", "origin", str(remote))


def _seed_ws9_surfaces(tmp_path: Path, *, head: str) -> None:
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
            "validated_head_sha": head,
            "platform_block": {"http_status": 403, "message": "blocked"},
        },
    )
    _write_json(
        reports / "ci_gate_promotion_receipt.json",
        {
            "schema_id": "kt.sovereign.ci_gate_promotion_receipt.v1",
            "status": "PASS_WITH_PLATFORM_BLOCK",
            "head_sha": head,
        },
    )
    _write_json(reports / "cryptographic_publication_receipt.json", {"schema_id": "kt.operator.cryptographic_publication_receipt.v1", "status": "PASS"})
    _write_json(
        reports / "cryptographic_publication" / "authority_subject.json",
        {
            "schema_id": "kt.authority.subject.v1",
            "truth_subject_commit": head,
            "truth_produced_at_commit": head,
        },
    )
    _write_json(
        reports / "kt_truth_publication_stabilization_receipt.json",
        {
            "schema_id": "kt.operator.truth_publication_stabilization_receipt.v2",
            "status": "PASS",
            "truth_publication_stabilized": True,
            "truth_subject_commit": head,
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
            "truth_subject_commit": head,
            "truth_produced_at_commit": head,
        },
    )
    _write_json(reports / "documentary_truth_validation_receipt.json", {"schema_id": "kt.operator.documentary_truth_validation_receipt.v1", "status": "PASS"})
    _write_json(
        reports / "public_verifier_manifest.json",
        {
            "schema_id": "kt.public_verifier_manifest.v4",
            "status": "HOLD",
            "evidence_commit": head,
            "truth_subject_commit": head,
            "subject_verdict": SUBJECT_VERDICT_PROVEN,
            "publication_receipt_status": "PASS",
            "evidence_contains_subject": True,
            "evidence_equals_subject": True,
            "claim_boundary": "subject equals evidence",
            "platform_governance_subject_commit": head,
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
            "truth_subject_commit": head,
            "posture_enum": "TRUTHFUL_GREEN",
        },
    )
    _write_json(
        ledger / "current_state_receipt.json",
        {
            "schema_id": "kt.operator.current_state_receipt.v4",
            "validated_head_sha": head,
            "branch_ref": "main",
            "posture_state": "TRUTHFUL_GREEN",
        },
    )
    _write_json(
        ledger / "runtime_closure_audit.json",
        {
            "schema_id": "kt.operator.runtime_closure_audit.v4",
            "validated_head_sha": head,
            "branch_ref": "main",
            "posture_state": "TRUTHFUL_GREEN",
        },
    )
    _write_json(
        main_truth / "current_pointer.json",
        {
            "schema_id": "kt.operator.truth_pointer.v1",
            "truth_subject_commit": head,
            "status": "SUPERSEDED_DOCUMENTARY_ONLY",
            "documentary_only": True,
            "live_authority": False,
        },
    )
    _write_json(
        reports / "current_state_receipt.json",
        {
            "schema_id": "kt.operator.current_state_receipt.v3",
            "validated_head_sha": head,
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
            "validated_head_sha": head,
            "status": "PASS",
            "posture_state": "TRUTHFUL_GREEN",
            "documentary_only": True,
            "live_authority": False,
        },
    )


def test_verify_fails_closed_on_stale_ws9_receipts(tmp_path: Path) -> None:
    _init_repo_with_remote(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    _seed_ws9_surfaces(tmp_path, head=head)
    _git_call(tmp_path, "add", ".")
    _git_call(tmp_path, "commit", "-m", "seed ws9")
    _git_call(tmp_path, "push", "-u", "origin", "main")
    _git_call(tmp_path, "push", "origin", "HEAD:refs/heads/kt_truth_ledger")
    _git_call(tmp_path, "fetch", "origin", "kt_truth_ledger")

    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _write_json(
        reports / "authority_convergence_receipt.json",
        {
            "schema_id": "kt.operator.authority_convergence_receipt.v2",
            "status": "FAIL",
            "proof_class": "FAIL_CLOSED",
            "published_head_authority_claimed": False,
            "current_head_authority_claimed": False,
            "h1_admissible": False,
            "failures": ["stale"],
            "observed": {"truth_subject_commit": "old", "ledger_branch_published": False},
        },
    )
    _write_json(
        reports / "published_head_self_convergence_receipt.json",
        {
            "schema_id": "kt.operator.published_head_self_convergence_receipt.v2",
            "status": "FAIL_CLOSED",
            "proof_class": "FAIL_CLOSED",
            "validated_head_sha": "old",
            "truth_subject_commit": "old",
            "evidence_commit": "old",
            "current_head_commit": "old",
            "head_equals_subject": False,
            "current_head_claim_verdict": "HEAD_TRANSPARENCY_CLAIM_UNPROVEN",
            "published_head_authority_claimed": False,
            "current_head_authority_claimed": False,
            "ledger_branch_published": False,
            "ledger_branch_head_sha": "",
            "main_live_truth_purged": False,
            "blockers": ["stale"],
        },
    )

    receipt = verify_reporting_integrity(root=tmp_path)
    assert receipt["status"] == "FAIL_CLOSED", receipt
    assert receipt["stale_findings"], receipt


def test_repair_recomputes_ws9_reporting_receipts(tmp_path: Path) -> None:
    _init_repo_with_remote(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    _seed_ws9_surfaces(tmp_path, head=head)
    _git_call(tmp_path, "add", ".")
    _git_call(tmp_path, "commit", "-m", "seed ws9")
    _git_call(tmp_path, "push", "-u", "origin", "main")
    _git_call(tmp_path, "push", "origin", "HEAD:refs/heads/kt_truth_ledger")
    _git_call(tmp_path, "fetch", "origin", "kt_truth_ledger")

    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _write_json(
        reports / "authority_convergence_receipt.json",
        {
            "schema_id": "kt.operator.authority_convergence_receipt.v2",
            "status": "FAIL",
            "proof_class": "FAIL_CLOSED",
            "published_head_authority_claimed": False,
            "current_head_authority_claimed": False,
            "h1_admissible": False,
            "failures": ["stale"],
            "observed": {"truth_subject_commit": "old", "ledger_branch_published": False},
        },
    )
    _write_json(
        reports / "published_head_self_convergence_receipt.json",
        {
            "schema_id": "kt.operator.published_head_self_convergence_receipt.v2",
            "status": "FAIL_CLOSED",
            "proof_class": "FAIL_CLOSED",
            "validated_head_sha": "old",
            "truth_subject_commit": "old",
            "evidence_commit": "old",
            "current_head_commit": "old",
            "head_equals_subject": False,
            "current_head_claim_verdict": "HEAD_TRANSPARENCY_CLAIM_UNPROVEN",
            "published_head_authority_claimed": False,
            "current_head_authority_claimed": False,
            "ledger_branch_published": False,
            "ledger_branch_head_sha": "",
            "main_live_truth_purged": False,
            "blockers": ["stale"],
        },
    )

    repair = repair_reporting_integrity(root=tmp_path)
    assert repair["status"] == "PASS", repair
    assert repair["verification_after"]["status"] == "PASS", repair

    auth = json.loads((reports / "authority_convergence_receipt.json").read_text(encoding="utf-8"))
    assert auth["status"] == "PASS"
    assert auth["proof_class"] == "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN"
    assert auth["observed"]["truth_subject_commit"] == head
    assert auth["observed"]["ledger_branch_published"] is True

    published = json.loads((reports / "published_head_self_convergence_receipt.json").read_text(encoding="utf-8"))
    assert published["status"] == "PASS"
    assert published["validated_head_sha"] == head
    assert published["ledger_branch_published"] is True
    assert published["ledger_branch_head_sha"]


def test_verify_tolerates_post_evidence_head_advance(tmp_path: Path) -> None:
    _init_repo_with_remote(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    _seed_ws9_surfaces(tmp_path, head=head)
    _git_call(tmp_path, "add", ".")
    _git_call(tmp_path, "commit", "-m", "seed ws9")
    _git_call(tmp_path, "push", "-u", "origin", "main")
    _git_call(tmp_path, "push", "origin", "HEAD:refs/heads/kt_truth_ledger")
    _git_call(tmp_path, "fetch", "origin", "kt_truth_ledger")

    repair = repair_reporting_integrity(root=tmp_path)
    assert repair["status"] == "PASS", repair

    (tmp_path / "EVIDENCE_ONLY.txt").write_text("evidence\n", encoding="utf-8", newline="\n")
    _git_call(tmp_path, "add", "EVIDENCE_ONLY.txt")
    _git_call(tmp_path, "commit", "-m", "advance evidence head")

    verify = verify_reporting_integrity(root=tmp_path)
    assert verify["status"] == "PASS", verify
    assert verify["current_git_head"] != head
