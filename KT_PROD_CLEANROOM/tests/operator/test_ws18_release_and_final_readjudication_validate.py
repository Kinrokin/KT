from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.ws18_release_and_final_readjudication_validate import (  # noqa: E402
    ACCEPTANCE_POLICY_REL,
    BLOCKER_MATRIX_REL,
    EXECUTION_DAG_REL,
    FINAL_READJUDICATION_RECEIPT_REL,
    NEXT_WORKSTREAM_ON_PASS,
    PASS_VERDICT,
    RELEASE_CEREMONY_REL,
    RELEASE_STATUS_RECEIPT_REL,
    SIGNER_TOPOLOGY_REL,
    TEST_REL,
    TOOL_REL,
    TRUST_ROOT_POLICY_REL,
    WS10_RECEIPT_REL,
    WS11_RECEIPT_REL,
    WS12_RECEIPT_REL,
    WS13_RECEIPT_REL,
    WS14_RECEIPT_REL,
    WS15_COMPILER_REL,
    WS15_RECEIPT_REL,
    WS16_RECEIPT_REL,
    WS17A_RECEIPT_REL,
    WS17B_RECEIPT_REL,
    emit_ws18_release_and_final_readjudication,
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def _git(tmp_path: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(tmp_path), *args], text=True, encoding="utf-8").strip()


def _commit_all(tmp_path: Path, message: str) -> str:
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", message)
    return _git(tmp_path, "rev-parse", "HEAD")


def _init_git_repo(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test User")


def _seed_ws18_repo(tmp_path: Path) -> str:
    _init_git_repo(tmp_path)
    (tmp_path / "README.md").write_text("seed\n", encoding="utf-8")
    tool_source = Path(__file__).resolve().parents[2] / "tools/operator/ws18_release_and_final_readjudication_validate.py"
    (tmp_path / TOOL_REL).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / TOOL_REL).write_text(tool_source.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    (tmp_path / TEST_REL).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / TEST_REL).write_text("seed\n", encoding="utf-8", newline="\n")
    ws17b_frozen_head = _commit_all(tmp_path, "freeze ws17b boundary")

    _write_json(tmp_path / WS10_RECEIPT_REL, {"schema_id": "kt.operator.root_ceremony_receipt.v1", "status": "PASS"})
    _write_json(tmp_path / WS11_RECEIPT_REL, {"schema_id": "kt.operator.sigstore_integration_receipt.v1", "status": "PASS"})
    _write_json(tmp_path / WS12_RECEIPT_REL, {"schema_id": "kt.operator.supply_chain_policy_receipt.v1", "status": "PASS"})
    _write_json(tmp_path / WS13_RECEIPT_REL, {"schema_id": "kt.operator.determinism_envelope_receipt.v1", "status": "PASS"})
    _write_json(tmp_path / WS14_RECEIPT_REL, {"schema_id": "kt.operator.public_verifier_release_receipt.v1", "status": "PASS"})
    _write_json(tmp_path / WS15_RECEIPT_REL, {"schema_id": "kt.operator.claim_abi_receipt.v1", "status": "PASS"})
    _write_json(
        tmp_path / WS15_COMPILER_REL,
        {
            "schema_id": "kt.operator.claim_proof_ceiling_compiler.v1",
            "status": "PASS",
            "blocked_current_claim_ids": [
                "campaign_completion_proven",
                "original_planned_3_of_5_root_execution_proven",
                "release_readiness_proven",
                "threshold_root_verifier_acceptance_active",
            ],
            "proof_ceiling_summary": {
                "release_state": "NOT_READY",
                "campaign_state": "NOT_COMPLETE",
                "verifier_acceptance": "BOOTSTRAP_ROOT_ONLY",
            },
        },
    )
    _write_json(tmp_path / WS16_RECEIPT_REL, {"schema_id": "kt.operator.tevv_dataset_registry_receipt.v1", "status": "PASS"})
    _write_json(
        tmp_path / WS17A_RECEIPT_REL,
        {
            "schema_id": "kt.operator.ws17a.external_assurance_confirmation_receipt.v1",
            "status": "PASS",
            "bounded_assurance_subject_head_commit": "a2cc7ba323cf143def4133d722a7e79dbf35729b",
        },
    )
    _write_json(
        tmp_path / WS17B_RECEIPT_REL,
        {
            "schema_id": "kt.operator.ws17b.external_capability_confirmation_receipt.v1",
            "status": "PASS",
            "compiled_against": ws17b_frozen_head,
            "current_repo_head": ws17b_frozen_head,
            "capability_scope": "HISTORICAL_BOUNDED_FRONTIER_TARGET_ONLY",
        },
    )
    _write_json(
        tmp_path / ACCEPTANCE_POLICY_REL,
        {
            "schema_id": "kt.governance.public_verifier_acceptance_policy.v1",
            "status": "ACTIVE",
            "accepted_verifier_trust_roots": [{"trust_root_id": "KT_TUF_ROOT_BOOTSTRAP_20260314", "acceptance_state": "ACTIVE_BOOTSTRAP_ACCEPTED"}],
            "pending_not_yet_accepted_trust_roots": [{"trust_root_id": "KT_SOVEREIGN_ROOT_TARGET_20260317", "acceptance_state": "PENDING_LATER_ACCEPTANCE_UPDATE"}],
        },
    )
    _write_json(
        tmp_path / SIGNER_TOPOLOGY_REL,
        {
            "schema_id": "kt.governance.signer_topology.v1",
            "status": "EXECUTED_RERATIFIED_3_OF_3",
            "roles": [
                {"role_id": "root", "issuance_state": "EXECUTED_OFFBOX_RERATIFIED_3_OF_3"},
                {"role_id": "release", "issuance_state": "PLANNED_PENDING_OFFBOX_CEREMONY"},
                {"role_id": "producer", "issuance_state": "PLANNED_PENDING_OFFBOX_CEREMONY"},
            ],
        },
    )
    _write_json(
        tmp_path / TRUST_ROOT_POLICY_REL,
        {
            "schema_id": "kt.governance.trust_root_policy.v1",
            "status": "EXECUTED_RERATIFIED_3_OF_3",
            "semantic_boundary": {"verifier_acceptance_upgraded": False},
        },
    )
    _write_json(
        tmp_path / RELEASE_CEREMONY_REL,
        {
            "schema_id": "kt.governance.release_ceremony.v1",
            "status": "ACTIVE_LOCKED_PENDING_UPSTREAM_WORKSTREAMS",
            "execution_prerequisites_not_yet_met": [
                "threshold-root verifier acceptance bundle published and accepted",
                "release signer issuance completed under later workstream law",
                "producer attestation bundle activated under later workstream law",
                "final readjudication completed in WS18",
            ],
            "semantic_boundary": {"release_ready_now": False},
        },
    )
    _write_json(
        tmp_path / EXECUTION_DAG_REL,
        {
            "schema_id": "kt.governance.execution_dag.v1",
            "status": "ACTIVE",
            "current_node": "WS17B_EXTERNAL_CONFIRMATION_CAPABILITY",
            "current_repo_head": ws17b_frozen_head,
            "next_lawful_workstream": "WS18_RELEASE_CEREMONY_AND_FINAL_READJUDICATION",
            "semantic_boundary": {"lawful_current_claim": "seed", "stronger_claim_not_made": []},
            "nodes": [
                {"id": "WS17A_EXTERNAL_CONFIRMATION_ASSURANCE", "status": "PASS", "ratification_checkpoint": "kt_external_assurance_confirmation_receipt.json"},
                {"id": "WS17B_EXTERNAL_CONFIRMATION_CAPABILITY", "status": "PASS", "ratification_checkpoint": "kt_external_capability_confirmation_receipt.json"},
                {"id": "WS18_RELEASE_CEREMONY_AND_FINAL_READJUDICATION", "status": "UNLOCKED", "ratification_checkpoint": "final_readjudication_receipt"},
                {"id": NEXT_WORKSTREAM_ON_PASS, "status": "LOCKED_PENDING_WS18_PASS", "ratification_checkpoint": "product_surface_receipt"},
            ],
        },
    )
    _commit_all(tmp_path, "seed ws18 inputs")
    return _git(tmp_path, "rev-parse", "HEAD")


def test_emit_ws18_passes_with_non_executed_release_boundary(tmp_path: Path) -> None:
    current_head = _seed_ws18_repo(tmp_path)
    receipt = emit_ws18_release_and_final_readjudication(root=tmp_path)
    assert receipt["status"] == "PASS"
    assert receipt["pass_verdict"] == PASS_VERDICT
    assert receipt["compiled_against"] == current_head
    assert receipt["final_verdict"]["release_eligibility"] == "NOT_ELIGIBLE"
    assert "THRESHOLD_ROOT_VERIFIER_ACCEPTANCE_PENDING" in receipt["final_verdict"]["open_blockers"]
    assert (tmp_path / BLOCKER_MATRIX_REL).exists()
    assert (tmp_path / RELEASE_STATUS_RECEIPT_REL).exists()
    assert (tmp_path / FINAL_READJUDICATION_RECEIPT_REL).exists()


def test_emit_ws18_blocks_when_ws17b_boundary_was_not_frozen_first(tmp_path: Path) -> None:
    _seed_ws18_repo(tmp_path)
    broken = json.loads((tmp_path / WS17B_RECEIPT_REL).read_text(encoding="utf-8"))
    broken["compiled_against"] = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    _write_json(tmp_path / WS17B_RECEIPT_REL, broken)
    _commit_all(tmp_path, "break ws17b freeze boundary")
    receipt = emit_ws18_release_and_final_readjudication(root=tmp_path)
    assert receipt["status"] == "BLOCKED"
    assert "RELEASE_STATUS_NOT_DETERMINED" in receipt["blocked_by"]
    release_status = json.loads((tmp_path / RELEASE_STATUS_RECEIPT_REL).read_text(encoding="utf-8"))
    assert "WS17B_BOUNDARY_NOT_FROZEN_FIRST" in release_status["blocked_by"]
