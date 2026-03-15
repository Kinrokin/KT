from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.public_verifier_release_validate import (
    CLAIM_COMPILER_ACTIVATION_RECEIPT_REL,
    CLAIM_COMPILER_POLICY_REL,
    COMMERCIAL_COMPILER_RECEIPT_REL,
    COMPETITION_PROFILE_REL,
    DOCTRINE_MANIFEST_REL,
    DOCTRINE_RATIFICATION_LOG_REL,
    OUTSIDER_PROFILE_REL,
    PUBLICATION_PROFILE_REL,
    PUBLIC_VERIFIER_ATTESTATION_REL,
    PUBLIC_VERIFIER_CONTRACT_REL,
    PUBLIC_VERIFIER_MANIFEST_REL,
    PUBLIC_VERIFIER_RELEASE_MANIFEST_REL,
    PUBLIC_VERIFIER_SBOM_REL,
    RELEASE_READINESS_MATRIX_REL,
    emit_public_verifier_release_bundle,
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


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


def _seed_public_verifier_sources(tmp_path: Path, *, forbidden_runtime_import: bool = False) -> None:
    runtime_import = "from tools.temple.runtime import bad\n" if forbidden_runtime_import else ""
    _write_text(
        tmp_path / "KT_PROD_CLEANROOM/tools/operator/public_verifier.py",
        "from tools.operator.platform_governance_narrowing import build_platform_governance_claims\n"
        "from tools.operator.titanium_common import load_json\n"
        f"{runtime_import}",
    )
    _write_text(tmp_path / "KT_PROD_CLEANROOM/tools/operator/platform_governance_narrowing.py", "from tools.operator.titanium_common import load_json\n")
    _write_text(
        tmp_path / "KT_PROD_CLEANROOM/tools/operator/titanium_common.py",
        "from tools.verification.strict_json import load_no_dupes\nfrom tools.canonicalize.kt_canonicalize import canonicalize_bytes\n",
    )
    _write_text(tmp_path / "KT_PROD_CLEANROOM/tools/verification/strict_json.py", "def load_no_dupes(path):\n    return {}\n")
    _write_text(tmp_path / "KT_PROD_CLEANROOM/tools/canonicalize/kt_canonicalize.py", "def canonicalize_bytes(value):\n    return b''\n")
    if forbidden_runtime_import:
        _write_text(tmp_path / "KT_PROD_CLEANROOM/tools/temple/runtime.py", "BAD = True\n")


def _seed_contracts_and_receipts(tmp_path: Path, *, head_sha: str, truth_subject_commit: str) -> None:
    _write_json(
        tmp_path / PUBLIC_VERIFIER_CONTRACT_REL,
        {
            "verifier_id": "KT_PUBLIC_VERIFIER_CONTRACT_V1",
            "supported_proof_classes": [
                "PUBLISHED_HEAD_TRANSPARENCY_VERIFIED_SUBJECT",
                "WORKFLOW_GOVERNANCE_ONLY",
                "CANONICAL_RUNTIME_BOUNDARY_SETTLED",
            ],
            "required_inputs": [
                PUBLIC_VERIFIER_MANIFEST_REL,
                "KT_PROD_CLEANROOM/reports/cryptographic_publication_receipt.json",
                "KT_PROD_CLEANROOM/reports/platform_governance_narrowing_receipt.json",
                "KT_PROD_CLEANROOM/reports/runtime_boundary_integrity_receipt.json",
                "KT_PROD_CLEANROOM/reports/kt_claim_ceiling_summary.json",
            ],
            "offline_verification_capable": True,
            "subject_evidence_boundary_rules": [
                "If current HEAD differs from truth_subject_commit, HEAD may only be described as containing evidence for the subject."
            ],
            "fail_closed_conditions": ["missing_required_input", "subject_evidence_boundary_ambiguous"],
            "allowed_contract_dependencies": [PUBLIC_VERIFIER_MANIFEST_REL],
            "forbidden_runtime_dependencies": ["KT_ARCHIVE/**", "docs/generated/**"],
        },
    )
    _write_json(
        tmp_path / CLAIM_COMPILER_POLICY_REL,
        {
            "always_on_surfaces": [
                "docs/generated/**",
                "KT_PROD_CLEANROOM/docs/commercial/**",
                "KT_PROD_CLEANROOM/reports/kt_release_readiness_matrix.json",
                "KT_PROD_CLEANROOM/reports/commercial_claim_compiler_receipt.json",
            ]
        },
    )
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/cryptographic_publication_receipt.json", {"status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/cryptographic_publication/authority_subject.json", {"truth_subject_commit": truth_subject_commit})
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM/reports/main_branch_protection_receipt.json",
        {"status": "BLOCKED", "claim_admissible": False, "validated_head_sha": "c" * 40, "platform_block": {"http_status": 403}},
    )
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/ci_gate_promotion_receipt.json", {"status": "PASS_WITH_PLATFORM_BLOCK", "head_sha": "c" * 40})
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM/reports/platform_governance_narrowing_receipt.json",
        {
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
            "platform_block": {"http_status": 403},
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM/reports/runtime_boundary_integrity_receipt.json",
        {
            "status": "PASS",
            "runtime_boundary_subject_commit": "d" * 40,
            "runtime_boundary_verdict": "CANONICAL_RUNTIME_BOUNDARY_SETTLED",
            "runtime_boundary_claim_admissible": True,
            "runtime_boundary_claim_boundary": "runtime boundary",
            "canonical_runtime_roots": ["core", "kt"],
            "compatibility_allowlist_roots": ["tools"],
        },
    )
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/settled_truth_source_receipt.json", {"authoritative_current_pointer_ref": "kt_truth_ledger:ledger/current/current_pointer.json"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/authority_convergence_receipt.json", {"status": "FAIL", "failures": ["AUTHORITY_CONVERGENCE_UNRESOLVED"]})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/kt_claim_ceiling_summary.json", {"highest_attained_proof_class": {"proof_class": "FRONTIER_SETTLEMENT_WITH_H1_BLOCK"}})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/kt_tuf_root_initialization.json", {"trust_root_id": "KT_TUF_ROOT_BOOTSTRAP_TEST"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/kt_sigstore_publication_bundle.json", {"status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/kt_rekor_inclusion_receipt.json", {"status": "PASS", "log_id": "log", "log_index": 7})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/kt_truth_publication_stabilization_receipt.json", {"status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/governance/program_catalog.json", {"programs": [{"program_id": "program.safe_run", "implementation_path": "KT_PROD_CLEANROOM/tools/operator/kt_cli.py"}]})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json", {"status": "HOLD", "validated_head_sha": head_sha})


def _seed_public_surfaces(tmp_path: Path) -> None:
    _write_json(tmp_path / DOCTRINE_MANIFEST_REL, {"source_refs": ["KT_PROD_CLEANROOM/reports/public_verifier_manifest.json", "KT_PROD_CLEANROOM/reports/kt_claim_ceiling_summary.json"]})
    _write_json(
        tmp_path / DOCTRINE_RATIFICATION_LOG_REL,
        {
            "prohibitions": [
                "generated doctrine may not phrase HEAD as verified subject unless SHAs match",
                "generated doctrine may not claim H1_ALLOWED while blockers remain open",
            ]
        },
    )
    _write_json(tmp_path / OUTSIDER_PROFILE_REL, {"current_status": "ADMISSIBLE_WITH_BOUNDARIES", "forbidden_claims": ["HEAD_IS_VERIFIED_SUBJECT", "H1_ALLOWED"]})
    _write_json(tmp_path / COMPETITION_PROFILE_REL, {"current_status": "BLOCKED", "forbidden_claims": ["COMPETITION_READY", "H1_ALLOWED"]})
    _write_json(tmp_path / PUBLICATION_PROFILE_REL, {"current_status": "BLOCKED", "forbidden_claims": ["PUBLICATION_READY", "HEAD_IS_VERIFIED_SUBJECT", "H1_ALLOWED"]})
    _write_json(
        tmp_path / RELEASE_READINESS_MATRIX_REL,
        {"profiles": [{"profile_id": "publication", "forbidden_claims": ["HEAD_IS_VERIFIED_SUBJECT", "H1_ALLOWED"], "evidence_refs": ["KT_PROD_CLEANROOM/reports/public_verifier_manifest.json"]}]},
    )
    _write_text(
        tmp_path / "KT_PROD_CLEANROOM/docs/commercial/KT_CERTIFICATION_PACK.md",
        "Documentary-only commercial surface.\nCurrent-tense claims are bound by KT_PROD_CLEANROOM/reports/commercial_claim_compiler_receipt.json.\nActive truth source: kt_truth_ledger:ledger/current/current_pointer.json.\nVerifier source: KT_PROD_CLEANROOM/reports/public_verifier_manifest.json.\nDocumentary mirror: KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json.\n",
    )
    _write_text(
        tmp_path / "KT_PROD_CLEANROOM/docs/commercial/KT_OPERATOR_FACTORY_SKU_CATALOG.md",
        "Documentary-only commercial surface.\nCurrent-tense claims are bound by KT_PROD_CLEANROOM/reports/commercial_claim_compiler_receipt.json.\nActive truth source: kt_truth_ledger:ledger/current/current_pointer.json.\nVerifier source: KT_PROD_CLEANROOM/reports/public_verifier_manifest.json.\n",
    )


def _seed_minimal_ws8_repo(tmp_path: Path, *, forbidden_runtime_import: bool = False) -> None:
    _init_git_repo(tmp_path)
    (tmp_path / "README.md").write_text("base\n", encoding="utf-8")
    _seed_public_verifier_sources(tmp_path, forbidden_runtime_import=forbidden_runtime_import)
    base = _commit_all(tmp_path, "base")
    _seed_contracts_and_receipts(tmp_path, head_sha=base, truth_subject_commit="b" * 40)
    _seed_public_surfaces(tmp_path)
    _commit_all(tmp_path, "seed ws8 repo")


def test_emit_public_verifier_release_bundle_passes_and_writes_release_artifacts(tmp_path: Path) -> None:
    _seed_minimal_ws8_repo(tmp_path)

    receipt = emit_public_verifier_release_bundle(root=tmp_path)

    assert receipt["status"] == "PASS"
    assert receipt["pass_verdict"] == "PUBLIC_VERIFIER_AND_CLAIM_COMPILER_ACTIVE"
    assert receipt["unexpected_touches"] == []
    assert receipt["protected_touch_violations"] == []
    assert (tmp_path / PUBLIC_VERIFIER_RELEASE_MANIFEST_REL).exists()
    assert (tmp_path / PUBLIC_VERIFIER_SBOM_REL).exists()
    assert (tmp_path / PUBLIC_VERIFIER_ATTESTATION_REL).exists()
    assert (tmp_path / CLAIM_COMPILER_ACTIVATION_RECEIPT_REL).exists()
    assert (tmp_path / COMMERCIAL_COMPILER_RECEIPT_REL).exists()


def test_emit_public_verifier_release_bundle_fails_on_forbidden_runtime_dependency(tmp_path: Path) -> None:
    _seed_minimal_ws8_repo(tmp_path, forbidden_runtime_import=True)

    with pytest.raises(RuntimeError, match="dependency boundary is not releasable"):
        emit_public_verifier_release_bundle(root=tmp_path)
