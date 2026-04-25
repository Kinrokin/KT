from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.ws15_claim_abi_validate import (  # noqa: E402
    ACCEPTANCE_POLICY_REL,
    CLAIM_ABI_POLICY_REL,
    CLAIM_CEILING_SUMMARY_REL,
    CLAIM_COMPILER_POLICY_REL,
    CURRENT_STATE_RECEIPT_REL,
    EXECUTION_DAG_REL,
    FAILURE_MODE_REGISTER_REL,
    IDENTITY_MODEL_POLICY_REL,
    LEDGER_LAW_REL,
    NEXT_WORKSTREAM_ID,
    PROOF_CEILING_COMPILER_REL,
    RECEIPT_REL,
    RELEASE_CEREMONY_REL,
    SETTLED_TRUTH_SOURCE_REL,
    SIGNER_IDENTITY_POLICY_REL,
    SIGNER_TOPOLOGY_REL,
    STEP_ID,
    TRUTH_SUPERSESSION_RECEIPT_REL,
    TRUTH_SUPERSESSION_RULES_REL,
    TRUST_ROOT_POLICY_REL,
    WS10_RECEIPT_REL,
    WS11_RECEIPT_REL,
    WS12_RECEIPT_REL,
    WS13_RECEIPT_REL,
    WS14_RECEIPT_REL,
    WORKSTREAM_ID,
    emit_ws15_claim_abi,
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


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


def _seed_ws15_repo(tmp_path: Path) -> str:
    _init_git_repo(tmp_path)
    (tmp_path / "README.md").write_text("seed\n", encoding="utf-8")
    _commit_all(tmp_path, "seed base")

    _write_json(
        tmp_path / EXECUTION_DAG_REL,
        {
            "current_node": WORKSTREAM_ID,
            "current_repo_head": "PLACEHOLDER",
            "dag_id": "KT_SOVEREIGN_EXECUTION_DAG_V1_20260317",
            "generated_utc": "2026-03-18T06:00:00Z",
            "next_lawful_workstream": WORKSTREAM_ID,
            "nodes": [
                {"id": WORKSTREAM_ID, "ratification_checkpoint": "claim_abi_receipt", "status": "UNLOCKED"},
                {"id": NEXT_WORKSTREAM_ID, "ratification_checkpoint": "tevv_and_benchmark_receipt", "status": "LOCKED_PENDING_WS15_PASS"},
            ],
            "schema_id": "kt.governance.execution_dag.v1",
            "semantic_boundary": {"lawful_current_claim": "seed", "stronger_claim_not_made": []},
            "status": "ACTIVE",
        },
    )
    _write_json(tmp_path / WS10_RECEIPT_REL, {"schema_id": "kt.operator.root_ceremony_receipt.v1", "status": "PASS", "subject_head_commit": "ws10subject", "compiled_against": "ws10freeze"})
    _write_json(tmp_path / WS11_RECEIPT_REL, {"schema_id": "kt.operator.sigstore_integration_receipt.v1", "status": "PASS", "compiled_against": "ws11subject"})
    _write_json(tmp_path / WS12_RECEIPT_REL, {"schema_id": "kt.operator.supply_chain_policy_receipt.v1", "status": "PASS", "compiled_against": "ws12subject", "bounded_current_surface": "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json"})
    _write_json(tmp_path / WS13_RECEIPT_REL, {"schema_id": "kt.operator.ws13.determinism_envelope_receipt.v1", "status": "PASS", "compiled_against": "ws13subject"})
    _write_json(tmp_path / TRUST_ROOT_POLICY_REL, {"schema_id": "kt.governance.trust_root_policy.v1", "topology_reratification": {"approved_by_operator": "robert_thomas_king"}})
    _write_json(
        tmp_path / SIGNER_TOPOLOGY_REL,
        {
            "schema_id": "kt.governance.signer_topology.v1",
            "role_identity_map": [
                {"role_id": "root", "identity_id": "kevin_gratts"},
                {"role_id": "root", "identity_id": "jessica_lack"},
                {"role_id": "root", "identity_id": "ruthie_mckinley"},
                {"role_id": "release", "identity_id": "KT_RELEASE_SIGNER_A"},
                {"role_id": "release", "identity_id": "KT_RELEASE_SIGNER_B"},
                {"role_id": "producer", "identity_id": "KT_PRODUCER_SIGNER_A"},
                {"role_id": "ci", "identity_id": "KT_CI_SIGNER_A"},
                {"role_id": "verifier_acceptance", "identity_id": "KT_VERIFIER_ACCEPTANCE_A"},
            ],
        },
    )
    _write_json(
        tmp_path / SIGNER_IDENTITY_POLICY_REL,
        {
            "schema_id": "kt.governance.signer_identity_policy.v1",
            "allowed_signers": [
                {"mode": "cosign_keypair", "signer_id": "KT_OP1_COSIGN_KEYPAIR"},
                {"mode": "sigstore_keyless", "signer_id": "KT_CI_TRUTH_BARRIER_KEYLESS_MAIN"},
            ],
        },
    )
    _write_json(
        tmp_path / SETTLED_TRUTH_SOURCE_REL,
        {
            "schema_id": "kt.operator.settled_truth_source_receipt.v1",
            "status": "SETTLED_AUTHORITATIVE",
            "authoritative_current_pointer_ref": "kt_truth_ledger:ledger/current/current_pointer.json",
            "pinned_head_sha": "truthsubject",
        },
    )
    _write_json(tmp_path / TRUTH_SUPERSESSION_RULES_REL, {"schema_id": "kt.governance.truth_supersession_rules.v1", "supersede_when": ["tracked truth surface validated_head_sha != current head"], "superseded_outputs": ["KT_PROD_CLEANROOM/reports/current_state_receipt.json"], "receipt_output": "KT_PROD_CLEANROOM/reports/truth_supersession_receipt.json"})
    _write_json(tmp_path / TRUTH_SUPERSESSION_RECEIPT_REL, {"schema_id": "kt.operator.truth_supersession_receipt.v1", "status": "PASS", "authority_status": "SETTLED_AUTHORITATIVE"})
    _write_json(tmp_path / CURRENT_STATE_RECEIPT_REL, {"schema_id": "kt.operator.current_state_receipt.v3", "status": "PASS", "documentary_only": True, "live_authority": False, "mirror_class": "documentary_compatibility_surface", "validation_index_ref": "KT_PROD_CLEANROOM/reports/live_validation_index.json", "superseded_by": ["kt_truth_ledger:ledger/current/current_pointer.json"]})
    _write_json(tmp_path / CLAIM_CEILING_SUMMARY_REL, {"schema_id": "kt.operator.claim_ceiling_summary.v1", "closeout_verdict": "SEALED_WITH_OPEN_BLOCKERS"})
    _write_json(tmp_path / CLAIM_COMPILER_POLICY_REL, {"schema_id": "kt.closure_foundation.claim_compiler_policy.v1", "status": "ACTIVE"})
    _write_json(tmp_path / ACCEPTANCE_POLICY_REL, {"schema_id": "kt.governance.public_verifier_acceptance_policy.v1", "accepted_verifier_trust_roots": [{"acceptance_state": "ACTIVE_BOOTSTRAP_ACCEPTED"}], "pending_not_yet_accepted_trust_roots": [{"acceptance_state": "PENDING_LATER_ACCEPTANCE_UPDATE"}]})
    _write_json(tmp_path / RELEASE_CEREMONY_REL, {"schema_id": "kt.governance.release_ceremony.v0", "status": "PREPARED_NOT_EXECUTED"})
    _write_json(tmp_path / FAILURE_MODE_REGISTER_REL, {"schema_id": "kt.governance.failure_mode_register.v0", "status": "PREPARED_NOT_EXECUTED"})

    subject_head = _commit_all(tmp_path, "freeze ws14 boundary")
    _write_json(tmp_path / WS14_RECEIPT_REL, {"schema_id": "kt.operator.public_verifier_release_receipt.v1", "status": "PASS", "compiled_against": subject_head})
    _write_json(tmp_path / EXECUTION_DAG_REL, {**json.loads((tmp_path / EXECUTION_DAG_REL).read_text(encoding="utf-8")), "current_repo_head": subject_head})
    _commit_all(tmp_path, "add ws14 receipt")
    return _git(tmp_path, "rev-parse", "HEAD")


def test_emit_ws15_pass_locks_claim_abi_and_unlocks_ws16(tmp_path: Path) -> None:
    freeze_head = _seed_ws15_repo(tmp_path)

    receipt = emit_ws15_claim_abi(root=tmp_path)

    assert receipt["status"] == "PASS"
    assert receipt["step_id"] == STEP_ID
    assert receipt["compiled_against"] == freeze_head
    assert receipt["next_lawful_workstream"] == NEXT_WORKSTREAM_ID
    dag = json.loads((tmp_path / EXECUTION_DAG_REL).read_text(encoding="utf-8"))
    ws15 = next(row for row in dag["nodes"] if row["id"] == WORKSTREAM_ID)
    ws16 = next(row for row in dag["nodes"] if row["id"] == NEXT_WORKSTREAM_ID)
    assert ws15["status"] == "PASS"
    assert ws16["status"] == "UNLOCKED"
    compiler = json.loads((tmp_path / PROOF_CEILING_COMPILER_REL).read_text(encoding="utf-8"))
    assert "threshold_root_verifier_acceptance_active" in compiler["blocked_current_claim_ids"]
    assert "ws10_root_boundary_reratified_3_of_3_only" in compiler["allowed_current_claim_ids"]
    assert (tmp_path / CLAIM_ABI_POLICY_REL).exists()
    assert (tmp_path / IDENTITY_MODEL_POLICY_REL).exists()
    assert (tmp_path / LEDGER_LAW_REL).exists()
    assert (tmp_path / RELEASE_CEREMONY_REL).exists()
    assert (tmp_path / FAILURE_MODE_REGISTER_REL).exists()
    assert (tmp_path / RECEIPT_REL).exists()


def test_emit_ws15_partial_when_threshold_root_already_marked_active(tmp_path: Path) -> None:
    _seed_ws15_repo(tmp_path)
    _write_json(tmp_path / ACCEPTANCE_POLICY_REL, {"schema_id": "kt.governance.public_verifier_acceptance_policy.v1", "accepted_verifier_trust_roots": [{"acceptance_state": "ACTIVE_BOOTSTRAP_ACCEPTED"}], "pending_not_yet_accepted_trust_roots": [{"acceptance_state": "ACTIVE_THRESHOLD_ACCEPTED"}]})
    _commit_all(tmp_path, "modify acceptance policy")

    receipt = emit_ws15_claim_abi(root=tmp_path)

    assert receipt["status"] == "PARTIAL"
    assert "PROOF_CEILING_WIDENS_BEYOND_CURRENT_ACCEPTANCE_BOUNDARY" in receipt["blocked_by"]


def test_emit_ws15_fails_closed_when_repo_is_not_frozen(tmp_path: Path) -> None:
    _seed_ws15_repo(tmp_path)
    (tmp_path / "scratch.txt").write_text("dirty\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="WS15 requires a frozen repo except for the bounded WS15 write set"):
        emit_ws15_claim_abi(root=tmp_path)
