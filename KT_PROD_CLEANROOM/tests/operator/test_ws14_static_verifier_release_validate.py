from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.ws14_static_verifier_release_validate import (  # noqa: E402
    ACCEPTANCE_POLICY_REL,
    CI_KEYLESS_BUNDLE_REL,
    CI_KEYLESS_RECEIPT_REL,
    CI_SIGNED_SURFACE_REL,
    CI_TRUTH_DIAGNOSTIC_REL,
    DISTRIBUTION_POLICY_REL,
    EXECUTION_DAG_REL,
    KEYLESS_STATUS_REL,
    LOG_MONITOR_POLICY_REL,
    LOG_MONITOR_RECEIPT_REL,
    PUBLIC_KEY_REF,
    PUBLIC_VERIFIER_CONTRACT_REL,
    PUBLIC_VERIFIER_RULES_REL,
    PUBLIC_VERIFIER_SOURCE_REL,
    RECEIPT_REL,
    SIGNER_IDENTITY_POLICY_REL,
    SIGNER_TOPOLOGY_REL,
    STATIC_RELEASE_MANIFEST_REL,
    STATIC_VERIFIER_ATTESTATION_REL,
    STATIC_VERIFIER_SBOM_REL,
    SUPPLY_CHAIN_LAYOUT_REL,
    TRUTH_FRESHNESS_WINDOWS_REL,
    TRUST_ROOT_POLICY_REL,
    TUF_ROOT_INITIALIZATION_REL,
    WS13_RECEIPT_REL,
    emit_ws14_static_verifier_release,
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


def _seed_ws14_repo(tmp_path: Path) -> str:
    _init_git_repo(tmp_path)
    (tmp_path / "README.md").write_text("seed\n", encoding="utf-8")
    _commit_all(tmp_path, "seed base")

    (tmp_path / PUBLIC_VERIFIER_SOURCE_REL).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / PUBLIC_VERIFIER_SOURCE_REL).write_text(
        "from __future__ import annotations\n\n\ndef build_public_verifier():\n    return {'status': 'PASS'}\n",
        encoding="utf-8",
    )
    (tmp_path / PUBLIC_KEY_REF).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / PUBLIC_KEY_REF).write_text("dummy-public-key\n", encoding="utf-8")

    _write_json(tmp_path / PUBLIC_VERIFIER_CONTRACT_REL, {"schema_id": "kt.contract.public_verifier.v1", "status": "ACTIVE"})
    _write_json(tmp_path / PUBLIC_VERIFIER_RULES_REL, {"schema_id": "kt.governance.public_verifier_rules.v3", "status": "ACTIVE"})
    _write_json(
        tmp_path / EXECUTION_DAG_REL,
        {
            "current_node": "WS14_STATIC_VERIFIER_RELEASE_AND_ACCEPTANCE_POLICY",
            "current_repo_head": "PLACEHOLDER",
            "generated_utc": "2026-03-18T00:00:00Z",
            "next_lawful_workstream": "WS14_STATIC_VERIFIER_RELEASE_AND_ACCEPTANCE_POLICY",
            "nodes": [
                {"id": "WS14_STATIC_VERIFIER_RELEASE_AND_ACCEPTANCE_POLICY", "status": "UNLOCKED"},
                {"id": "WS15_CLAIM_ABI_PROOF_CEILING_IDENTITY_AND_LEDGER_LAW", "status": "LOCKED_PENDING_WS14_PASS"},
            ],
            "schema_id": "kt.governance.execution_dag.v1",
            "semantic_boundary": {"lawful_current_claim": "seed", "stronger_claim_not_made": []},
            "status": "ACTIVE",
        },
    )
    _write_json(
        tmp_path / TRUST_ROOT_POLICY_REL,
        {
            "closure_boundary": {"next_required_step": "WS14_STATIC_VERIFIER_RELEASE_AND_ACCEPTANCE_POLICY"},
            "current_repo_head": "PLACEHOLDER",
            "emergency_rotation_path": {"required_actions": ["freeze"], "triggers": ["compromise"]},
            "generated_utc": "2026-03-18T00:00:00Z",
            "inheritance": {"foundation_trust_root_id": "KT_TUF_ROOT_BOOTSTRAP_20260314"},
            "ratified_root_topology": {"target_trust_root_id": "KT_SOVEREIGN_ROOT_TARGET_20260317"},
            "schema_id": "kt.governance.trust_root_policy.v1",
            "semantic_boundary": {"lawful_current_claim": "seed", "verifier_acceptance_upgraded": False},
            "verifier_acceptance_impact": {
                "current_acceptance_state": "BOOTSTRAP_ROOT_ONLY",
                "current_boundary": "seed",
                "post_pass_target_state": "pending",
            },
        },
    )
    _write_json(
        tmp_path / SIGNER_TOPOLOGY_REL,
        {
            "current_repo_head": "PLACEHOLDER",
            "generated_utc": "2026-03-18T00:00:00Z",
            "schema_id": "kt.governance.signer_topology.v1",
            "semantic_boundary": {"lawful_current_claim": "seed"},
            "verifier_acceptance_impact": {"post_ws11_and_ws14": "seed"},
        },
    )
    _write_json(
        tmp_path / SIGNER_IDENTITY_POLICY_REL,
        {
            "allowed_signers": [
                {
                    "allowed_predicates": ["https://kings-theorem.io/attestations/kt-authority-subject/v1"],
                    "mode": "cosign_keypair",
                    "public_key_ref": PUBLIC_KEY_REF,
                    "public_key_sha256": "abc123",
                    "signer_id": "KT_OP1_COSIGN_KEYPAIR",
                },
                {
                    "allowed_predicates": ["https://kings-theorem.io/attestations/kt-authority-subject/v1"],
                    "certificate_identity": "https://github.com/Kinrokin/KT/.github/workflows/ci_truth_barrier.yml@refs/heads/main",
                    "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
                    "mode": "sigstore_keyless",
                    "signer_id": "KT_CI_TRUTH_BARRIER_KEYLESS_MAIN",
                },
            ],
            "rules": {"rekor_url_default": "https://rekor.sigstore.dev"},
            "schema_id": "kt.governance.signer_identity_policy.v1",
            "status": "ACTIVE",
        },
    )
    _write_json(
        tmp_path / SUPPLY_CHAIN_LAYOUT_REL,
        {
            "publication": {
                "statement_type": "https://in-toto.io/Statement/v0.1",
                "predicate_type": "https://kings-theorem.io/attestations/kt-authority-subject/v1",
            },
            "schema_id": "kt.governance.supply_chain_layout.v1",
            "status": "ACTIVE",
        },
    )
    _write_json(
        tmp_path / TRUTH_FRESHNESS_WINDOWS_REL,
        {
            "freshness_windows_hours": {"live_validation_index": 24},
            "schema_id": "kt.governance.truth_freshness_windows.v1",
            "staleness_is_fail_closed": True,
            "status": "ACTIVE",
        },
    )
    _write_json(
        tmp_path / LOG_MONITOR_POLICY_REL,
        {
            "anomaly_rules": [{"rule_id": "missing_keyless_bundle", "severity": "critical"}],
            "freeze_behavior": {"downstream_scope": "ws15_plus", "freeze_on_any_high_or_critical_anomaly": True},
            "schema_id": "kt.governance.log_monitor_policy.v1",
            "status": "ACTIVE",
        },
    )
    _write_json(
        tmp_path / LOG_MONITOR_RECEIPT_REL,
        {"freeze_state": "NO_FREEZE", "schema_id": "kt.operator.log_monitor_plane_receipt.v1", "status": "PASS"},
    )
    _write_json(
        tmp_path / KEYLESS_STATUS_REL,
        {"schema_id": "kt.operator.sigstore_keyless_status.v1", "status": "PASS"},
    )
    _write_json(
        tmp_path / TUF_ROOT_INITIALIZATION_REL,
        {"schema_id": "kt.operator.tuf_root_initialization.v1", "status": "PASS", "trust_root_id": "KT_TUF_ROOT_BOOTSTRAP_20260314"},
    )

    runtime_manifest = {
        "schema_id": "kt.public_verifier_manifest.v4",
        "status": "PASS",
        "validated_head_sha": "PLACEHOLDER",
    }
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json", runtime_manifest)

    _write_json(
        tmp_path / CI_TRUTH_DIAGNOSTIC_REL,
        {
            "run_id": "23229317266",
            "schema_id": "kt.operator.truth_barrier_remote_diagnostic.v1",
            "status": "PASS",
            "truth_barrier_step_outcome": "success",
        },
    )
    _write_json(tmp_path / CI_SIGNED_SURFACE_REL, runtime_manifest)
    _write_json(tmp_path / CI_KEYLESS_BUNDLE_REL, {"bundle": "ok"})
    signed_surface_sha = hashlib.sha256((tmp_path / CI_SIGNED_SURFACE_REL).read_bytes()).hexdigest()
    _write_json(
        tmp_path / CI_KEYLESS_RECEIPT_REL,
        {
            "certificate_identity": "https://github.com/Kinrokin/KT/.github/workflows/ci_truth_barrier.yml@refs/heads/main",
            "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
            "executed_signer_mode": "sigstore_keyless",
            "run_id": "23229317266",
            "schema_id": "kt.operator.ws11_keyless_execution_receipt.v1",
            "signed_surface_path": "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
            "signed_surface_sha256": signed_surface_sha,
            "status": "PASS",
            "verification_status": "PASS",
        },
    )
    subject_head = _commit_all(tmp_path, "freeze ws13 boundary")
    for rel in (EXECUTION_DAG_REL, TRUST_ROOT_POLICY_REL, SIGNER_TOPOLOGY_REL):
        payload = json.loads((tmp_path / rel).read_text(encoding="utf-8"))
        payload["current_repo_head"] = subject_head
        _write_json(tmp_path / rel, payload)
    _write_json(
        tmp_path / WS13_RECEIPT_REL,
        {
            "compiled_against": subject_head,
            "current_repo_head": subject_head,
            "schema_id": "kt.operator.ws13.determinism_envelope_receipt.v1",
            "status": "PASS",
        },
    )
    return subject_head


def test_emit_ws14_pass_locks_bootstrap_only_acceptance_policy(tmp_path: Path) -> None:
    subject_head = _seed_ws14_repo(tmp_path)

    receipt = emit_ws14_static_verifier_release(root=tmp_path)

    assert receipt["status"] == "PASS"
    assert receipt["blocked_by"] == []
    assert receipt["compiled_against"] == subject_head
    assert receipt["next_lawful_workstream"] == "WS15_CLAIM_ABI_PROOF_CEILING_IDENTITY_AND_LEDGER_LAW"
    acceptance_policy = json.loads((tmp_path / ACCEPTANCE_POLICY_REL).read_text(encoding="utf-8"))
    assert acceptance_policy["accepted_verifier_trust_roots"][0]["acceptance_state"] == "ACTIVE_BOOTSTRAP_ACCEPTED"
    assert acceptance_policy["pending_not_yet_accepted_trust_roots"][0]["acceptance_state"] == "PENDING_LATER_ACCEPTANCE_UPDATE"
    dag = json.loads((tmp_path / EXECUTION_DAG_REL).read_text(encoding="utf-8"))
    ws14 = next(row for row in dag["nodes"] if row["id"] == "WS14_STATIC_VERIFIER_RELEASE_AND_ACCEPTANCE_POLICY")
    ws15 = next(row for row in dag["nodes"] if row["id"] == "WS15_CLAIM_ABI_PROOF_CEILING_IDENTITY_AND_LEDGER_LAW")
    assert ws14["status"] == "PASS"
    assert ws15["status"] == "UNLOCKED"
    assert (tmp_path / STATIC_RELEASE_MANIFEST_REL).exists()
    assert (tmp_path / STATIC_VERIFIER_SBOM_REL).exists()
    assert (tmp_path / STATIC_VERIFIER_ATTESTATION_REL).exists()
    assert (tmp_path / DISTRIBUTION_POLICY_REL).exists()
    assert (tmp_path / RECEIPT_REL).exists()


def test_emit_ws14_partial_when_current_head_keyless_surface_is_not_proven(tmp_path: Path) -> None:
    _seed_ws14_repo(tmp_path)
    keyless_receipt = json.loads((tmp_path / CI_KEYLESS_RECEIPT_REL).read_text(encoding="utf-8"))
    keyless_receipt["verification_status"] = "FAIL"
    _write_json(tmp_path / CI_KEYLESS_RECEIPT_REL, keyless_receipt)

    receipt = emit_ws14_static_verifier_release(root=tmp_path)

    assert receipt["status"] == "PARTIAL"
    assert "DECLARED_CURRENT_HEAD_KEYLESS_SURFACE_NOT_PROVEN" in receipt["blocked_by"]
    dag = json.loads((tmp_path / EXECUTION_DAG_REL).read_text(encoding="utf-8"))
    ws15 = next(row for row in dag["nodes"] if row["id"] == "WS15_CLAIM_ABI_PROOF_CEILING_IDENTITY_AND_LEDGER_LAW")
    assert ws15["status"] == "LOCKED_PENDING_WS14_PASS"


def test_emit_ws14_fails_closed_when_required_ws13_input_is_missing(tmp_path: Path) -> None:
    _seed_ws14_repo(tmp_path)
    (tmp_path / CI_TRUTH_DIAGNOSTIC_REL).unlink()

    with pytest.raises(RuntimeError, match="missing required WS14 input"):
        emit_ws14_static_verifier_release(root=tmp_path)
