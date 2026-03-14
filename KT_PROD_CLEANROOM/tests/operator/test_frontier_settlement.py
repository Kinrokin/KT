from __future__ import annotations

import json
import subprocess
from pathlib import Path

from tools.operator.frontier_settlement import (
    FRONTIER_VERDICT_ALLOWED,
    FRONTIER_VERDICT_BLOCKED,
    H1_GATE_VERDICT_ALLOWED,
    H1_GATE_VERDICT_BLOCKED,
    build_frontier_settlement_receipt,
    build_h1_activation_gate_receipt,
    build_next_horizon_activation_receipt,
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


def _seed_frontier_inputs(
    tmp_path: Path,
    *,
    truth_publication_stabilized: bool,
    h1_activation_allowed: bool,
    published_head_proven: bool,
    authority_convergence_status: str,
) -> None:
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "execution_board.json",
        {
            "schema_id": "kt.governance.execution_board.v3",
            "program_gates": {
                "TRUTH_PUBLICATION_STABILIZED": truth_publication_stabilized,
                "H1_ACTIVATION_ALLOWED": h1_activation_allowed,
            },
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
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "published_head_self_convergence_receipt.json",
        {
            "schema_id": "kt.operator.published_head_self_convergence_receipt.v1",
            "status": "PASS" if published_head_proven else "LOCAL_LEDGER_SELF_CONVERGENCE_ONLY",
            "proof_class": (
                "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN"
                if published_head_proven
                else "LOCAL_LEDGER_SELF_CONVERGENCE_ONLY"
            ),
            "validated_head_sha": "e" * 40,
            "published_head_authority_claimed": published_head_proven,
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "authority_convergence_receipt.json",
        {
            "schema_id": "kt.operator.authority_convergence_receipt.v1",
            "status": authority_convergence_status,
            "proof_class": "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN" if authority_convergence_status == "PASS" else "FAIL_CLOSED",
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "representative_authority_lane_reproducibility_receipt.json",
        {
            "schema_id": "kt.operator.representative_authority_lane_reproducibility_receipt.v1",
            "status": "PASS",
            "validated_head_sha": "f" * 40,
            "representative_authority_lane_proven": True,
            "representative_authority_lane_program_id": "program.red_assault.serious_v1",
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "proofrunbundle_index.json",
        {
            "schema_id": "kt.sovereign.proofrunbundle_index.v1",
            "status": "PASS",
            "bundles": [
                {"program_id": "program.certify.canonical_hmac", "proof_id": "certify", "validated_head_sha": "f" * 40},
                {"program_id": "program.hat_demo", "proof_id": "hat_demo", "validated_head_sha": "f" * 40},
                {
                    "program_id": "program.red_assault.serious_v1",
                    "proof_id": "red_assault_serious_v1",
                    "validated_head_sha": "f" * 40,
                },
            ],
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "commercial_claim_compiler_receipt.json",
        {
            "schema_id": "kt.operator.commercial_claim_compiler_receipt.v1",
            "status": "PASS",
            "compiled_head_commit": "9" * 40,
            "active_truth_source_ref": "kt_truth_ledger:ledger/current/current_pointer.json",
            "documentary_mirror_ref": "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
        },
    )


def test_frontier_settlement_blocks_h1_when_published_head_not_proven(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    (tmp_path / "README.md").write_text("base\n", encoding="utf-8")
    _commit_all(tmp_path, "base")
    _seed_frontier_inputs(
        tmp_path,
        truth_publication_stabilized=False,
        h1_activation_allowed=False,
        published_head_proven=False,
        authority_convergence_status="FAIL",
    )
    _commit_all(tmp_path, "seed receipts")

    h1_gate = build_h1_activation_gate_receipt(root=tmp_path)
    next_horizon = build_next_horizon_activation_receipt(root=tmp_path)
    frontier = build_frontier_settlement_receipt(root=tmp_path)

    assert h1_gate["status"] == "BLOCKED"
    assert h1_gate["h1_gate_verdict"] == H1_GATE_VERDICT_BLOCKED
    assert h1_gate["h1_allowed"] is False
    assert "PUBLISHED_HEAD_SELF_CONVERGENCE_UNRESOLVED" in h1_gate["blockers"]
    assert next_horizon["status"] == "HOLD"
    assert next_horizon["activation_allowed"] is False
    assert any("published_head_self_convergence_receipt.json" in row for row in next_horizon["prerequisites_missing"])
    assert frontier["status"] == "PASS"
    assert frontier["frontier_settlement_verdict"] == FRONTIER_VERDICT_BLOCKED
    assert frontier["h1_allowed"] is False
    assert frontier["runtime_boundary_head_claim_verdict"] == "HEAD_CONTAINS_RUNTIME_BOUNDARY_EVIDENCE_FOR_SUBJECT"
    assert len(frontier["demonstrated_programs"]) == 3


def test_frontier_settlement_allows_single_adapter_h1_when_gate_and_publication_are_proven(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    (tmp_path / "README.md").write_text("base\n", encoding="utf-8")
    _commit_all(tmp_path, "base")
    _seed_frontier_inputs(
        tmp_path,
        truth_publication_stabilized=True,
        h1_activation_allowed=True,
        published_head_proven=True,
        authority_convergence_status="PASS",
    )
    _commit_all(tmp_path, "seed receipts")

    h1_gate = build_h1_activation_gate_receipt(root=tmp_path)
    next_horizon = build_next_horizon_activation_receipt(root=tmp_path)
    frontier = build_frontier_settlement_receipt(root=tmp_path)

    assert h1_gate["status"] == "PASS"
    assert h1_gate["h1_gate_verdict"] == H1_GATE_VERDICT_ALLOWED
    assert h1_gate["h1_allowed"] is True
    assert h1_gate["single_adapter_benchmarking_allowed"] is True
    assert h1_gate["router_and_multi_adapter_blocked"] is True
    assert next_horizon["status"] == "READY"
    assert next_horizon["activation_allowed"] is True
    assert frontier["status"] == "PASS"
    assert frontier["frontier_settlement_verdict"] == FRONTIER_VERDICT_ALLOWED
    assert frontier["h1_allowed"] is True
