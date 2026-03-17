from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.ws11_sigstore_rekor_log_monitor_validate import (  # noqa: E402
    EXECUTION_DAG_REL,
    KEYLESS_POLICY_REL,
    KEYLESS_STATUS_REL,
    LOG_MONITOR_POLICY_REL,
    LOG_MONITOR_RECEIPT_REL,
    PUBLIC_TRUST_BUNDLE_REL,
    RECEIPT_REL,
    SIGNER_POLICY_REL,
    SIGNER_TOPOLOGY_REL,
    TRUST_ROOT_POLICY_REL,
    WS10_RESEAL_RECEIPT_REL,
    emit_ws11_sigstore_activation,
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


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


def _seed_ws11_repo(tmp_path: Path, *, keyless_allowed: bool = False, keyless_bundle: bool = False) -> None:
    _init_git_repo(tmp_path)
    (tmp_path / "README.md").write_text("base\n", encoding="utf-8")

    _write_json(
        tmp_path / WS10_RESEAL_RECEIPT_REL,
        {
            "status": "PASS",
            "import_path_fragility_note": "test_root_ceremony_prepare.py passes from package root and fails from repo root with ModuleNotFoundError: tools.",
        },
    )
    _write_json(
        tmp_path / SIGNER_POLICY_REL,
        {
            "schema_id": "kt.governance.signer_identity_policy.v1",
            "status": "ACTIVE",
            "allowed_signers": [
                {
                    "signer_id": "KT_OP1_COSIGN_KEYPAIR" if not keyless_bundle else "KT_OP1_SIGSTORE_KEYLESS",
                    "mode": "cosign_keypair" if not keyless_bundle else "sigstore_keyless",
                    "public_key_ref": "KT_PROD_CLEANROOM/governance/signers/kt_op1_cosign.pub",
                }
            ],
            "keyless_constraints": {
                "allowed": keyless_allowed,
                "certificate_identity": "spiffe://kt/ws11" if keyless_allowed else "",
                "certificate_oidc_issuer": "https://issuer.example" if keyless_allowed else "",
            },
        },
    )
    _write_text(tmp_path / "KT_PROD_CLEANROOM/governance/signers/kt_op1_cosign.pub", "PUBLIC KEY\n")
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM/reports/kt_sigstore_publication_bundle.json",
        {
            "status": "PASS",
            "signer_id": "KT_OP1_SIGSTORE_KEYLESS" if keyless_bundle else "KT_OP1_COSIGN_KEYPAIR",
            "signer_mode": "sigstore_keyless" if keyless_bundle else "cosign_keypair",
            "certificate_identity": "spiffe://kt/ws11" if keyless_bundle else "",
            "certificate_oidc_issuer": "https://issuer.example" if keyless_bundle else "",
            "truth_subject_commit": "d56de5c40345c0c187f6ebca1b0727ff0f5cefd7",
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM/reports/kt_rekor_inclusion_receipt.json",
        {
            "status": "PASS",
            "log_id": "rekor-log-id",
            "log_index": 17,
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
        {
            "evidence_commit": "13163fc3343bcc05101f07911a8aa0e22b41aca4",
            "claim_boundary": "Current HEAD contains evidence for the subject only.",
        },
    )
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/kt_public_verifier_release_manifest.json", {"status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/kt_public_verifier_attestation.json", {"status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/kt_tuf_root_initialization.json", {"status": "PASS"})
    _write_json(
        tmp_path / EXECUTION_DAG_REL,
        {
            "schema_id": "kt.governance.execution_dag.v1",
            "generated_utc": "2026-03-17T19:52:21Z",
            "current_repo_head": "seed",
            "current_node": "WS11_SIGSTORE_REKOR_AND_LOG_MONITOR_ACTIVATION",
            "next_lawful_workstream": "WS11_SIGSTORE_REKOR_AND_LOG_MONITOR_ACTIVATION",
            "semantic_boundary": {"lawful_current_claim": "seed claim"},
            "nodes": [
                {"id": "WS10_AIR_GAPPED_ROOT_CEREMONY_AND_SIGNER_TOPOLOGY", "status": "PASS_RERATIFIED_3_OF_3"},
                {
                    "id": "WS11_SIGSTORE_REKOR_AND_LOG_MONITOR_ACTIVATION",
                    "status": "UNLOCKED",
                    "ratification_checkpoint": "kt_sigstore_integration_receipt.json",
                },
                {"id": "WS12_IN_TOTO_SLSA_AND_TUF_ATTACK_COVERAGE", "status": "LOCKED_PENDING_WS11_PASS"},
            ],
        },
    )
    _write_json(
        tmp_path / TRUST_ROOT_POLICY_REL,
        {
            "schema_id": "kt.governance.trust_root_policy.v1",
            "generated_utc": "2026-03-17T19:32:42Z",
            "current_repo_head": "seed",
            "semantic_boundary": {"lawful_current_claim": "WS11 has not started."},
            "closure_boundary": {"next_required_step": "WS11_SIGSTORE_REKOR_AND_LOG_MONITOR_ACTIVATION"},
        },
    )
    _write_json(
        tmp_path / SIGNER_TOPOLOGY_REL,
        {
            "schema_id": "kt.governance.signer_topology.v1",
            "generated_utc": "2026-03-17T19:32:42Z",
            "current_repo_head": "seed",
            "semantic_boundary": {"lawful_current_claim": "WS11 has not started."},
        },
    )

    _commit_all(tmp_path, "seed ws11 repo")


def test_emit_ws11_partial_when_keyless_path_not_active(tmp_path: Path) -> None:
    _seed_ws11_repo(tmp_path, keyless_allowed=False, keyless_bundle=False)

    receipt = emit_ws11_sigstore_activation(root=tmp_path)

    assert receipt["status"] == "PARTIAL"
    assert "KEYLESS_SIGNER_POLICY_DISABLED" in receipt["blocked_by"]
    assert receipt["truth_conditions"]["rekor_inclusion_evidence_exists"] is True
    assert receipt["truth_conditions"]["kt_log_monitor_active_as_real_plane"] is True
    assert receipt["truth_conditions"]["outsider_verification_has_no_private_local_secret_dependency_for_declared_ws11_surfaces"] is True

    dag = json.loads((tmp_path / EXECUTION_DAG_REL).read_text(encoding="utf-8"))
    ws11 = next(row for row in dag["nodes"] if row["id"] == "WS11_SIGSTORE_REKOR_AND_LOG_MONITOR_ACTIVATION")
    ws12 = next(row for row in dag["nodes"] if row["id"] == "WS12_IN_TOTO_SLSA_AND_TUF_ATTACK_COVERAGE")
    assert ws11["status"] == "PARTIAL_KEYPAIR_PUBLIC_ONLY"
    assert ws12["status"] == "LOCKED_PENDING_WS11_PASS"

    assert (tmp_path / KEYLESS_POLICY_REL).exists()
    assert (tmp_path / LOG_MONITOR_POLICY_REL).exists()
    assert (tmp_path / KEYLESS_STATUS_REL).exists()
    assert (tmp_path / LOG_MONITOR_RECEIPT_REL).exists()
    assert (tmp_path / PUBLIC_TRUST_BUNDLE_REL).exists()
    assert (tmp_path / RECEIPT_REL).exists()


def test_emit_ws11_pass_when_keyless_constraints_and_bundle_are_present(tmp_path: Path) -> None:
    _seed_ws11_repo(tmp_path, keyless_allowed=True, keyless_bundle=True)

    receipt = emit_ws11_sigstore_activation(root=tmp_path)

    assert receipt["status"] == "PASS"
    assert receipt["blocked_by"] == []
    dag = json.loads((tmp_path / EXECUTION_DAG_REL).read_text(encoding="utf-8"))
    ws12 = next(row for row in dag["nodes"] if row["id"] == "WS12_IN_TOTO_SLSA_AND_TUF_ATTACK_COVERAGE")
    assert ws12["status"] == "UNLOCKED"


def test_emit_ws11_fails_closed_when_rekor_receipt_is_missing(tmp_path: Path) -> None:
    _seed_ws11_repo(tmp_path, keyless_allowed=False, keyless_bundle=False)
    (tmp_path / "KT_PROD_CLEANROOM/reports/kt_rekor_inclusion_receipt.json").unlink()
    _commit_all(tmp_path, "remove rekor receipt")

    with pytest.raises(RuntimeError, match="missing required WS11 input"):
        emit_ws11_sigstore_activation(root=tmp_path)
