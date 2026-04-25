from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.claim_compiler import build_claim_compiler_receipt  # noqa: E402
from tools.operator.public_verifier import build_public_verifier_report  # noqa: E402


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


def _seed_docs(tmp_path: Path) -> None:
    shared_lines = [
        "Documentary-only commercial surface.",
        "Current-tense claims are bound by KT_PROD_CLEANROOM/reports/commercial_claim_compiler_receipt.json.",
        "Active truth source: kt_truth_ledger:ledger/current/current_pointer.json.",
        "Verifier source: KT_PROD_CLEANROOM/reports/public_verifier_manifest.json.",
    ]
    (tmp_path / "KT_PROD_CLEANROOM" / "docs" / "commercial").mkdir(parents=True, exist_ok=True)
    (tmp_path / "KT_PROD_CLEANROOM" / "docs" / "commercial" / "KT_CERTIFICATION_PACK.md").write_text(
        "\n".join([*shared_lines, "Documentary mirror: KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json."]) + "\n",
        encoding="utf-8",
    )
    (tmp_path / "KT_PROD_CLEANROOM" / "docs" / "commercial" / "KT_OPERATOR_FACTORY_SKU_CATALOG.md").write_text(
        "\n".join(shared_lines) + "\n",
        encoding="utf-8",
    )


def _seed_receipts(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "main_branch_protection_receipt.json",
        {"schema_id": "kt.main_branch_protection_receipt.v2", "status": "BLOCKED", "claim_admissible": False, "platform_block": {"http_status": 403}, "validated_head_sha": "c" * 40},
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "ci_gate_promotion_receipt.json",
        {"schema_id": "kt.sovereign.ci_gate_promotion_receipt.v1", "status": "PASS_WITH_PLATFORM_BLOCK", "head_sha": "c" * 40},
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
            "compatibility_allowlist_roots": [],
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "settled_truth_source_receipt.json",
        {"schema_id": "kt.operator.settled_truth_source_receipt.v1", "authoritative_current_pointer_ref": "kt_truth_ledger:ledger/current/current_pointer.json"},
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "program_catalog.json",
        {"schema_id": "kt.operator.program_catalog.v1", "programs": [{"program_id": "program.safe_run", "implementation_path": "KT_PROD_CLEANROOM/tools/operator/kt_cli.py"}]},
    )


def test_wave1_toolchain_observability_emits_public_verifier_and_claim_compiler_events(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    (tmp_path / "README.md").write_text("base\n", encoding="utf-8")
    _commit_all(tmp_path, "base")
    _seed_receipts(tmp_path)
    _seed_docs(tmp_path)
    _commit_all(tmp_path, "seed receipts")

    telemetry_path = tmp_path / "toolchain.jsonl"
    report = build_public_verifier_report(root=tmp_path, telemetry_path=telemetry_path)
    receipt = build_claim_compiler_receipt(root=tmp_path, telemetry_path=telemetry_path)

    rows = [json.loads(line) for line in telemetry_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    surfaces = {row["surface_id"] for row in rows}

    assert report["status"] in {"PASS", "HOLD"}
    assert receipt["status"] == "PASS"
    assert "tools.operator.public_verifier.build_public_verifier_report" in surfaces
    assert "tools.operator.claim_compiler.build_claim_compiler_receipt" in surfaces
