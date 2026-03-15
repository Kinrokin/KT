from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.public_verifier import (
    HEAD_VERDICT_CONTAINS,
    GOVERNANCE_HEAD_VERDICT_WORKFLOW_CONTAINS,
    SUBJECT_VERDICT_PROVEN,
    build_public_verifier_claims,
    build_public_verifier_report,
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _git(tmp_path: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(tmp_path), *args], text=True).strip()


def _commit_all(tmp_path: Path, message: str) -> str:
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", message)
    return _git(tmp_path, "rev-parse", "HEAD")


def _init_git_repo(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test User")


def _write_platform_governance_receipts(tmp_path: Path, subject_head: str) -> None:
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "main_branch_protection_receipt.json",
        {
            "schema_id": "kt.main_branch_protection_receipt.v2",
            "status": "BLOCKED",
            "claim_admissible": False,
            "platform_block": {"http_status": 403, "message": "blocked"},
            "validated_head_sha": subject_head,
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "ci_gate_promotion_receipt.json",
        {
            "schema_id": "kt.sovereign.ci_gate_promotion_receipt.v1",
            "status": "PASS_WITH_PLATFORM_BLOCK",
            "head_sha": subject_head,
        },
    )


def test_build_public_verifier_claims_reads_distinct_evidence_and_subject_commits(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    (tmp_path / "README.md").write_text("base\n", encoding="utf-8")
    _commit_all(tmp_path, "base")

    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cryptographic_publication_receipt.json",
        {"schema_id": "test.receipt.v1", "status": "PASS"},
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cryptographic_publication" / "authority_subject.json",
        {"schema_id": "test.subject.v1", "truth_subject_commit": "c" * 40},
    )
    evidence_commit = _commit_all(tmp_path, "ws6 evidence")

    (tmp_path / "notes.txt").write_text("later\n", encoding="utf-8")
    _commit_all(tmp_path, "later change")

    claims = build_public_verifier_claims(root=tmp_path, live_head="a" * 40)

    assert claims["evidence_commit"] == evidence_commit
    assert claims["truth_subject_commit"] == "c" * 40
    assert claims["subject_verdict"] == SUBJECT_VERDICT_PROVEN
    assert claims["publication_receipt_status"] == "PASS"
    assert claims["evidence_contains_subject"] is True
    assert claims["evidence_equals_subject"] is False


def test_build_public_verifier_report_fail_closes_head_claim_to_contains_evidence(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    (tmp_path / "README.md").write_text("base\n", encoding="utf-8")
    _commit_all(tmp_path, "base")
    _write_platform_governance_receipts(tmp_path, "c" * 40)

    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "public_verifier_manifest.json",
        {
            "schema_id": "kt.public_verifier_manifest.v4",
            "status": "HOLD",
            "evidence_commit": "a" * 40,
            "truth_subject_commit": "b" * 40,
            "subject_verdict": SUBJECT_VERDICT_PROVEN,
            "publication_receipt_status": "PASS",
            "evidence_contains_subject": True,
            "evidence_equals_subject": False,
            "claim_boundary": "evidence commit and subject commit are distinct",
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
                "KT_PROD_CLEANROOM/reports/platform_governance_narrowing_receipt.json",
            ],
            "publication_evidence_refs": [
                "KT_PROD_CLEANROOM/reports/cryptographic_publication_receipt.json",
                "KT_PROD_CLEANROOM/reports/cryptographic_publication/authority_subject.json",
            ],
        },
    )
    _commit_all(tmp_path, "manifest")

    (tmp_path / "later.txt").write_text("head drift\n", encoding="utf-8")
    current_head = _commit_all(tmp_path, "later change")

    report = build_public_verifier_report(root=tmp_path)

    assert report["current_head_commit"] == current_head
    assert report["evidence_commit"] == "a" * 40
    assert report["truth_subject_commit"] == "b" * 40
    assert report["head_equals_subject"] is False
    assert report["head_claim_verdict"] == HEAD_VERDICT_CONTAINS
    assert report["platform_governance_verdict"] == "WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED"
    assert report["platform_governance_subject_commit"] == "c" * 40
    assert report["platform_governance_claim_admissible"] is False
    assert report["workflow_governance_status"] == "PASS_WITH_PLATFORM_BLOCK"
    assert report["branch_protection_status"] == "BLOCKED"
    assert report["enterprise_legitimacy_ceiling"] == "WORKFLOW_GOVERNANCE_ONLY"
    assert report["platform_governance_head_equals_subject"] is False
    assert report["platform_governance_head_claim_verdict"] == GOVERNANCE_HEAD_VERDICT_WORKFLOW_CONTAINS
