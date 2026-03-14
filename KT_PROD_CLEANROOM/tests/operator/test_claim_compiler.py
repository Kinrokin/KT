from __future__ import annotations

import json
import subprocess
from pathlib import Path

from tools.operator.claim_compiler import build_claim_compiler_receipt


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


def _seed_receipts(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "main_branch_protection_receipt.json",
        {
            "schema_id": "kt.main_branch_protection_receipt.v2",
            "status": "BLOCKED",
            "claim_admissible": False,
            "platform_block": {"http_status": 403, "message": "blocked"},
            "validated_head_sha": "c" * 40,
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "ci_gate_promotion_receipt.json",
        {
            "schema_id": "kt.sovereign.ci_gate_promotion_receipt.v1",
            "status": "PASS_WITH_PLATFORM_BLOCK",
            "head_sha": "c" * 40,
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "public_verifier_manifest.json",
        {
            "schema_id": "kt.public_verifier_manifest.v4",
            "status": "HOLD",
            "evidence_commit": "a" * 40,
            "truth_subject_commit": "b" * 40,
            "subject_verdict": "PUBLISHED_HEAD_TRANSPARENCY_VERIFIED",
            "publication_receipt_status": "PASS",
            "evidence_contains_subject": True,
            "evidence_equals_subject": False,
            "claim_boundary": "truth boundary",
            "platform_governance_subject_commit": "c" * 40,
            "platform_governance_verdict": "WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED",
            "platform_governance_claim_admissible": False,
            "workflow_governance_status": "PASS_WITH_PLATFORM_BLOCK",
            "branch_protection_status": "BLOCKED",
            "platform_governance_claim_boundary": "governance boundary",
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
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "runtime_boundary_integrity_receipt.json",
        {
            "schema_id": "kt.operator.runtime_boundary_integrity_receipt.v1",
            "status": "PASS",
            "runtime_boundary_subject_commit": "d" * 40,
            "runtime_boundary_verdict": "CANONICAL_RUNTIME_BOUNDARY_SETTLED",
            "runtime_boundary_claim_admissible": True,
            "runtime_boundary_claim_boundary": "runtime boundary",
            "canonical_runtime_roots": ["core", "kt"],
            "compatibility_allowlist_roots": ["tools"],
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "settled_truth_source_receipt.json",
        {
            "schema_id": "kt.operator.settled_truth_source_receipt.v1",
            "authoritative_current_pointer_ref": "kt_truth_ledger:ledger/current/current_pointer.json",
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "program_catalog.json",
        {
            "schema_id": "kt.operator.program_catalog.v1",
            "programs": [
                {
                    "program_id": "program.safe_run",
                    "implementation_path": "KT_PROD_CLEANROOM/tools/operator/kt_cli.py",
                }
            ],
        },
    )


def _seed_docs(tmp_path: Path, *, include_required_markers: bool) -> None:
    shared_lines = [
        "Documentary-only commercial surface.",
        "Current-tense claims are bound by KT_PROD_CLEANROOM/reports/commercial_claim_compiler_receipt.json.",
        "Active truth source: kt_truth_ledger:ledger/current/current_pointer.json.",
        "Verifier source: KT_PROD_CLEANROOM/reports/public_verifier_manifest.json.",
    ]
    pack_lines = [*shared_lines, "Documentary mirror: KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json."]
    catalog_lines = list(shared_lines)
    if not include_required_markers:
        pack_lines = ["missing markers"]
        catalog_lines = ["missing markers"]
    (tmp_path / "KT_PROD_CLEANROOM" / "docs" / "commercial").mkdir(parents=True, exist_ok=True)
    (tmp_path / "KT_PROD_CLEANROOM" / "docs" / "commercial" / "KT_CERTIFICATION_PACK.md").write_text(
        "\n".join(pack_lines) + "\n",
        encoding="utf-8",
    )
    (tmp_path / "KT_PROD_CLEANROOM" / "docs" / "commercial" / "KT_OPERATOR_FACTORY_SKU_CATALOG.md").write_text(
        "\n".join(catalog_lines) + "\n",
        encoding="utf-8",
    )


def test_claim_compiler_passes_when_docs_and_receipts_are_aligned(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    (tmp_path / "README.md").write_text("base\n", encoding="utf-8")
    _commit_all(tmp_path, "base")
    _seed_receipts(tmp_path)
    _seed_docs(tmp_path, include_required_markers=True)
    _commit_all(tmp_path, "seed receipts")

    receipt = build_claim_compiler_receipt(root=tmp_path)

    assert receipt["status"] == "PASS"
    assert receipt["active_truth_source_ref"] == "kt_truth_ledger:ledger/current/current_pointer.json"
    assert receipt["compiled_head_commit"] == receipt["current_head_commit"]
    assert receipt["truth_head_claim_verdict"] == "HEAD_CONTAINS_TRANSPARENCY_VERIFIED_SUBJECT_EVIDENCE"
    assert receipt["platform_governance_head_claim_verdict"] == "HEAD_CONTAINS_WORKFLOW_GOVERNANCE_ONLY_EVIDENCE_FOR_SUBJECT"
    assert receipt["runtime_boundary_head_claim_verdict"] == "HEAD_CONTAINS_RUNTIME_BOUNDARY_EVIDENCE_FOR_SUBJECT"
    assert all("Current HEAD" not in claim for claim in receipt["allowed_current_claims"])
    assert all("Compiled head" in claim for claim in receipt["allowed_current_claims"][:3])


def test_claim_compiler_fails_when_commercial_docs_miss_required_markers(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    (tmp_path / "README.md").write_text("base\n", encoding="utf-8")
    _commit_all(tmp_path, "base")
    _seed_receipts(tmp_path)
    _seed_docs(tmp_path, include_required_markers=False)
    _commit_all(tmp_path, "seed receipts")

    receipt = build_claim_compiler_receipt(root=tmp_path)

    assert receipt["status"] == "FAIL"
    assert any(check["status"] == "FAIL" for check in receipt["commercial_doc_checks"])
