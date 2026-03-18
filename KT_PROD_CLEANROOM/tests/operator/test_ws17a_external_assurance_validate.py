from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.ws17a_external_assurance_validate import (  # noqa: E402
    ACCEPTANCE_POLICY_REL,
    DISTRIBUTION_POLICY_REL,
    EXECUTION_DAG_REL,
    IMPORT_MANIFEST_REL,
    KEYLESS_RECEIPT_REL,
    PASS_VERDICT,
    REPLAY_REPORT_REL,
    REMOTE_DIAGNOSTIC_REL,
    SIGNED_SURFACE_REL,
    SIGSTORE_BUNDLE_REL,
    STATIC_RELEASE_MANIFEST_REL,
    STATIC_VERIFIER_ATTESTATION_REL,
    TEST_REL,
    TOOL_REL,
    WS14_RECEIPT_REL,
    WS16_RECEIPT_REL,
    emit_ws17a_external_assurance,
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


def _seed_ws17a_repo(tmp_path: Path, *, secret_free: bool = True) -> str:
    _init_git_repo(tmp_path)
    (tmp_path / "README.md").write_text("seed\n", encoding="utf-8")
    tool_source = Path(__file__).resolve().parents[2] / "tools/operator/ws17a_external_assurance_validate.py"
    _write_text(tmp_path / TOOL_REL, tool_source.read_text(encoding="utf-8"))
    _write_text(tmp_path / TEST_REL, "seed\n")
    frozen_head = _commit_all(tmp_path, "freeze ws16 boundary")

    bounded_subject = "a2cc7ba323cf143def4133d722a7e79dbf35729b"
    surface_payload = {"schema_id": "kt.public_verifier_manifest.v4", "status": "PASS", "validated_head_sha": bounded_subject}
    _write_json(tmp_path / SIGNED_SURFACE_REL, surface_payload)
    signed_surface_sha = hashlib.sha256((tmp_path / SIGNED_SURFACE_REL).read_bytes()).hexdigest()
    bundle_payload = {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "abc"}}}
    _write_json(tmp_path / SIGSTORE_BUNDLE_REL, bundle_payload)
    bundle_sha = hashlib.sha256((tmp_path / SIGSTORE_BUNDLE_REL).read_bytes()).hexdigest()

    _write_json(tmp_path / WS14_RECEIPT_REL, {"schema_id": "kt.operator.public_verifier_release_receipt.v1", "status": "PASS", "compiled_against": bounded_subject})
    _write_json(
        tmp_path / WS16_RECEIPT_REL,
        {
            "schema_id": "kt.operator.tevv_dataset_registry_receipt.v1",
            "status": "PASS",
            "compiled_against": frozen_head,
            "current_repo_head": frozen_head,
            "tevv_subject_head_commit": bounded_subject,
            "dataset_hashes": {SIGNED_SURFACE_REL: signed_surface_sha, SIGSTORE_BUNDLE_REL: bundle_sha},
        },
    )
    _write_json(
        tmp_path / ACCEPTANCE_POLICY_REL,
        {
            "schema_id": "kt.governance.public_verifier_acceptance_policy.v1",
            "status": "ACTIVE",
            "ws13_subject_head_commit": bounded_subject,
            "accepted_signature_trust_roots": [
                {
                    "signer_id": "KT_CI_TRUTH_BARRIER_KEYLESS_MAIN",
                    "mode": "sigstore_keyless",
                    "certificate_identity": "https://github.com/Kinrokin/KT/.github/workflows/ci_truth_barrier.yml@refs/heads/main",
                    "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
                }
            ],
            "private_secret_dependency_rules": {
                "rule": "Declared verifier release surfaces must be verifiable from packaged public material only.",
                "allowed_public_material_refs": [SIGNED_SURFACE_REL, SIGSTORE_BUNDLE_REL, KEYLESS_RECEIPT_REL, REMOTE_DIAGNOSTIC_REL],
                "forbidden_inputs": ["private signing keys", "HMAC or environment-secret trust material"],
            },
        },
    )
    _write_json(
        tmp_path / DISTRIBUTION_POLICY_REL,
        {
            "schema_id": "kt.governance.public_verifier_distribution_policy.v1",
            "status": "ACTIVE",
            "no_private_secret_dependency": secret_free,
            "offline_verification_capable": True,
            "forbidden_distribution_channels": ["secret_backed_remote_verification"],
        },
    )
    _write_json(
        tmp_path / STATIC_RELEASE_MANIFEST_REL,
        {
            "schema_id": "kt.operator.static_verifier_release_manifest.v1",
            "status": "PASS",
            "acceptance_policy_ref": ACCEPTANCE_POLICY_REL,
            "distribution_policy_ref": DISTRIBUTION_POLICY_REL,
            "ws13_subject_head_commit": bounded_subject,
            "accepted_current_head_surface": {
                "signed_surface_import_ref": SIGNED_SURFACE_REL,
                "signed_surface_sha256": signed_surface_sha,
                "keyless_bundle_ref": SIGSTORE_BUNDLE_REL,
                "keyless_bundle_sha256": bundle_sha,
                "keyless_execution_receipt_ref": KEYLESS_RECEIPT_REL,
                "truth_barrier_diagnostic_ref": REMOTE_DIAGNOSTIC_REL,
                "keyless_execution_run_id": "23229317266",
            },
        },
    )
    _write_json(tmp_path / STATIC_VERIFIER_ATTESTATION_REL, {"schema_id": "kt.operator.static_verifier_attestation.v1", "status": "PASS", "current_repo_head": bounded_subject})
    _write_json(
        tmp_path / KEYLESS_RECEIPT_REL,
        {
            "schema_id": "kt.operator.ws11_keyless_execution_receipt.v1",
            "status": "PASS",
            "verification_status": "PASS",
            "executed_signer_mode": "sigstore_keyless",
            "executed_signer_id": "KT_CI_TRUTH_BARRIER_KEYLESS_MAIN",
            "certificate_identity": "https://github.com/Kinrokin/KT/.github/workflows/ci_truth_barrier.yml@refs/heads/main",
            "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
            "signed_surface_path": "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
            "signed_surface_sha256": signed_surface_sha,
            "bundle_sha256": bundle_sha,
            "keyless_backed_surfaces": ["KT_PROD_CLEANROOM/reports/public_verifier_manifest.json"],
            "run_id": "23229317266",
        },
    )
    _write_json(tmp_path / REMOTE_DIAGNOSTIC_REL, {"schema_id": "kt.operator.truth_barrier_remote_diagnostic.v1", "status": "PASS", "truth_barrier_step_outcome": "success", "run_id": "23229317266"})
    _write_json(
        tmp_path / EXECUTION_DAG_REL,
        {
            "schema_id": "kt.governance.execution_dag.v1",
            "status": "ACTIVE",
            "current_node": "WS17A_EXTERNAL_CONFIRMATION_ASSURANCE",
            "current_repo_head": frozen_head,
            "next_lawful_workstream": "WS17A_EXTERNAL_CONFIRMATION_ASSURANCE",
            "semantic_boundary": {"lawful_current_claim": "seed", "stronger_claim_not_made": []},
            "nodes": [
                {"id": "WS17A_EXTERNAL_CONFIRMATION_ASSURANCE", "status": "UNLOCKED", "ratification_checkpoint": "external_assurance_receipt"},
                {"id": "WS17B_EXTERNAL_CONFIRMATION_CAPABILITY", "status": "UNLOCKED", "ratification_checkpoint": "external_capability_receipt"},
                {"id": "WS18_RELEASE_CEREMONY_AND_FINAL_READJUDICATION", "status": "LOCKED_PENDING_WS17_PASS", "ratification_checkpoint": "final_readjudication_receipt"},
            ],
        },
    )
    return _commit_all(tmp_path, "seed ws17a inputs")


def test_emit_ws17a_passes_with_secret_free_detached_replay(tmp_path: Path) -> None:
    frozen_head = _seed_ws17a_repo(tmp_path)
    receipt = emit_ws17a_external_assurance(root=tmp_path)
    assert receipt["status"] == "PASS"
    assert receipt["pass_verdict"] == PASS_VERDICT
    assert receipt["compiled_against"] == frozen_head
    assert receipt["next_lawful_workstream"] == "WS17B_EXTERNAL_CONFIRMATION_CAPABILITY"
    assert (tmp_path / IMPORT_MANIFEST_REL).exists()
    assert (tmp_path / REPLAY_REPORT_REL).exists()
    replay = json.loads((tmp_path / REPLAY_REPORT_REL).read_text(encoding="utf-8"))
    assert replay["status"] == "PASS"


def test_emit_ws17a_blocks_when_distribution_policy_is_not_secret_free(tmp_path: Path) -> None:
    _seed_ws17a_repo(tmp_path, secret_free=False)
    receipt = emit_ws17a_external_assurance(root=tmp_path)
    assert receipt["status"] == "BLOCKED"
    assert "DISTRIBUTION_POLICY_NOT_SECRET_FREE" in receipt["blocked_by"]
