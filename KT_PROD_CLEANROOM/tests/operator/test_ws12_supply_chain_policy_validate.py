from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.ws12_supply_chain_policy_validate import (  # noqa: E402
    BUILD_PROVENANCE_REL,
    BUILD_VERIFICATION_RECEIPT_REL,
    CRYPTO_IN_TOTO_REL,
    EXECUTION_DAG_REL,
    LOCAL_TRUTH_INDEX_REL,
    LOG_MONITOR_POLICY_REL,
    PUBLIC_VERIFIER_MANIFEST_REL,
    RECEIPT_REL,
    REMOTE_KEYLESS_BUNDLE_REL,
    REMOTE_KEYLESS_RECEIPT_REL,
    REMOTE_SIGNED_SURFACE_REL,
    REMOTE_TRUTH_BARRIER_DIAGNOSTIC_REL,
    REMOTE_TRUTH_INDEX_REL,
    SIGNER_IDENTITY_POLICY_REL,
    SIGNER_TOPOLOGY_REL,
    SOURCE_IN_TOTO_REL,
    SUPPLY_CHAIN_LAYOUT_REL,
    TRUST_ROOT_POLICY_REL,
    VERIFICATION_SUMMARY_REL,
    WS11_KEYLESS_STATUS_REL,
    WS11_LOG_MONITOR_RECEIPT_REL,
    WS11_PUBLIC_TRUST_BUNDLE_REL,
    WS11_RECEIPT_REL,
    emit_ws12_supply_chain_policy,
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


def _truth_index(*, head: str, dirty: bool, pass_state: bool = True) -> dict:
    return {
        "schema_id": "kt.operator.live_validation_index.v1",
        "checks": [{"check_id": "current_worktree_cleanroom_suite", "critical": True, "status": "PASS" if pass_state else "FAIL"}],
        "worktree": {"head_sha": head, "git_dirty": dirty, "dirty_files": [] if not dirty else ["x"]},
    }


def _seed_ws12_repo(tmp_path: Path) -> str:
    _init_git_repo(tmp_path)
    (tmp_path / "README.md").write_text("base\n", encoding="utf-8")
    base_head = _commit_all(tmp_path, "seed base")

    _write_json(tmp_path / EXECUTION_DAG_REL, {"schema_id": "kt.governance.execution_dag.v1", "generated_utc": "2026-03-17T00:00:00Z", "current_repo_head": base_head, "current_node": "WS12_IN_TOTO_SLSA_AND_TUF_ATTACK_COVERAGE", "next_lawful_workstream": "WS12_IN_TOTO_SLSA_AND_TUF_ATTACK_COVERAGE", "semantic_boundary": {"lawful_current_claim": "seed"}, "nodes": [{"id": "WS11_SIGSTORE_REKOR_AND_LOG_MONITOR_ACTIVATION", "status": "PASS"}, {"id": "WS12_IN_TOTO_SLSA_AND_TUF_ATTACK_COVERAGE", "status": "UNLOCKED", "ratification_checkpoint": "kt_supply_chain_policy_receipt.json"}, {"id": "WS13_ARTIFACT_CLASS_AND_DETERMINISM_ENVELOPE_LOCK", "status": "LOCKED_PENDING_WS12_PASS"}]})
    _write_json(tmp_path / TRUST_ROOT_POLICY_REL, {"schema_id": "kt.governance.trust_root_policy.v1", "generated_utc": "2026-03-17T00:00:00Z", "current_repo_head": base_head, "closure_boundary": {"next_required_step": "WS12_IN_TOTO_SLSA_AND_TUF_ATTACK_COVERAGE"}, "semantic_boundary": {"verifier_acceptance_upgraded": False, "lawful_current_claim": "seed"}, "emergency_rotation_path": {"required_actions": ["freeze downstream workstreams", "convene new air-gapped ceremony"]}})
    _write_json(tmp_path / SIGNER_TOPOLOGY_REL, {"schema_id": "kt.governance.signer_topology.v1", "generated_utc": "2026-03-17T00:00:00Z", "current_repo_head": base_head, "semantic_boundary": {"lawful_current_claim": "seed"}})
    _write_json(tmp_path / SIGNER_IDENTITY_POLICY_REL, {"schema_id": "kt.governance.signer_identity_policy.v1", "keyless_constraints": {"allowed": True, "certificate_identity": "https://github.com/Kinrokin/KT/.github/workflows/ci_truth_barrier.yml@refs/heads/main", "certificate_oidc_issuer": "https://token.actions.githubusercontent.com"}})
    _write_json(tmp_path / LOG_MONITOR_POLICY_REL, {"schema_id": "kt.governance.log_monitor_policy.v1", "freeze_behavior": {"freeze_on_any_high_or_critical_anomaly": True}})
    _write_json(tmp_path / SUPPLY_CHAIN_LAYOUT_REL, {"schema_id": "kt.governance.supply_chain_layout.v1", "status": "ACTIVE", "expires_utc": "2026-09-13T00:00:00Z"})
    _write_json(tmp_path / WS11_RECEIPT_REL, {"status": "PASS"})
    _write_json(tmp_path / WS11_KEYLESS_STATUS_REL, {"status": "PASS"})
    _write_json(tmp_path / WS11_LOG_MONITOR_RECEIPT_REL, {"status": "PASS"})
    _write_json(tmp_path / WS11_PUBLIC_TRUST_BUNDLE_REL, {"status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/ws11_keyless/kt_truth_barrier_remote_diagnostic.json", {"truth_barrier_step_outcome": "failure"})
    _write_json(tmp_path / PUBLIC_VERIFIER_MANIFEST_REL, {"status": "PASS"})
    _write_json(tmp_path / SOURCE_IN_TOTO_REL, {"status": "PASS"})
    _write_json(tmp_path / CRYPTO_IN_TOTO_REL, {"status": "PASS"})
    _write_json(tmp_path / BUILD_PROVENANCE_REL, {"status": "PASS"})
    _write_json(tmp_path / VERIFICATION_SUMMARY_REL, {"status": "PASS"})
    _write_json(tmp_path / BUILD_VERIFICATION_RECEIPT_REL, {"status": "PASS"})
    seeded_head = _commit_all(tmp_path, "seed ws12 committed inputs")

    bundle_path = tmp_path / REMOTE_KEYLESS_BUNDLE_REL
    _write_text(tmp_path / REMOTE_SIGNED_SURFACE_REL, (tmp_path / PUBLIC_VERIFIER_MANIFEST_REL).read_text(encoding="utf-8"))
    _write_text(bundle_path, "{\"bundle\":\"ok\"}\n")
    _write_json(tmp_path / REMOTE_KEYLESS_RECEIPT_REL, {"status": "PASS", "verification_status": "PASS", "executed_signer_mode": "sigstore_keyless", "signed_surface_path": PUBLIC_VERIFIER_MANIFEST_REL, "signed_surface_sha256": hashlib.sha256((tmp_path / REMOTE_SIGNED_SURFACE_REL).read_bytes()).hexdigest(), "bundle_path": REMOTE_KEYLESS_BUNDLE_REL, "bundle_sha256": hashlib.sha256(bundle_path.read_bytes()).hexdigest(), "certificate_identity": "https://github.com/Kinrokin/KT/.github/workflows/ci_truth_barrier.yml@refs/heads/main", "certificate_oidc_issuer": "https://token.actions.githubusercontent.com", "keyless_backed_surfaces": [PUBLIC_VERIFIER_MANIFEST_REL], "run_id": "run-1"})
    _write_json(tmp_path / REMOTE_TRUTH_BARRIER_DIAGNOSTIC_REL, {"status": "PASS", "truth_barrier_step_outcome": "success", "truth_barrier_step_conclusion": "success", "run_id": "run-1", "workflow_ref": ".github/workflows/ci_truth_barrier.yml"})
    _write_json(tmp_path / LOCAL_TRUTH_INDEX_REL, _truth_index(head=seeded_head, dirty=False, pass_state=True))
    _write_json(tmp_path / REMOTE_TRUTH_INDEX_REL, _truth_index(head=seeded_head, dirty=False, pass_state=True))
    return seeded_head


def test_emit_ws12_pass_when_truth_planes_and_attack_coverage_hold(tmp_path: Path) -> None:
    head = _seed_ws12_repo(tmp_path)
    receipt = emit_ws12_supply_chain_policy(root=tmp_path)
    assert receipt["status"] == "PASS"
    assert receipt["blocked_by"] == []
    assert receipt["bounded_current_surface"] == PUBLIC_VERIFIER_MANIFEST_REL
    assert receipt["truth_plane_reconciliation"]["legacy_remote_failure_visible"] is True
    dag = json.loads((tmp_path / EXECUTION_DAG_REL).read_text(encoding="utf-8"))
    ws12 = next(row for row in dag["nodes"] if row["id"] == "WS12_IN_TOTO_SLSA_AND_TUF_ATTACK_COVERAGE")
    ws13 = next(row for row in dag["nodes"] if row["id"] == "WS13_ARTIFACT_CLASS_AND_DETERMINISM_ENVELOPE_LOCK")
    assert ws12["status"] == "PASS"
    assert ws13["status"] == "UNLOCKED"
    assert receipt["imported_evidence"]["imported_hashes"][REMOTE_KEYLESS_RECEIPT_REL]
    assert receipt["current_repo_head"] == head
    assert (tmp_path / RECEIPT_REL).exists()


def test_emit_ws12_partial_when_remote_truth_barrier_is_not_reconciled(tmp_path: Path) -> None:
    _seed_ws12_repo(tmp_path)
    _write_json(tmp_path / REMOTE_TRUTH_BARRIER_DIAGNOSTIC_REL, {"status": "FAIL", "truth_barrier_step_outcome": "failure", "truth_barrier_step_conclusion": "success", "run_id": "run-1", "workflow_ref": ".github/workflows/ci_truth_barrier.yml"})
    receipt = emit_ws12_supply_chain_policy(root=tmp_path)
    assert receipt["status"] == "PARTIAL"
    assert "REMOTE_TRUTH_BARRIER_DIAGNOSTIC_NOT_PASS" in receipt["blocked_by"]
    dag = json.loads((tmp_path / EXECUTION_DAG_REL).read_text(encoding="utf-8"))
    ws12 = next(row for row in dag["nodes"] if row["id"] == "WS12_IN_TOTO_SLSA_AND_TUF_ATTACK_COVERAGE")
    ws13 = next(row for row in dag["nodes"] if row["id"] == "WS13_ARTIFACT_CLASS_AND_DETERMINISM_ENVELOPE_LOCK")
    assert ws12["status"] == "PARTIAL_RECONCILIATION_PENDING"
    assert ws13["status"] == "LOCKED_PENDING_WS12_PASS"


def test_emit_ws12_fails_closed_when_imported_remote_keyless_receipt_is_missing(tmp_path: Path) -> None:
    _seed_ws12_repo(tmp_path)
    (tmp_path / REMOTE_KEYLESS_RECEIPT_REL).unlink()
    with pytest.raises(RuntimeError, match="missing required WS12 input"):
        emit_ws12_supply_chain_policy(root=tmp_path)
