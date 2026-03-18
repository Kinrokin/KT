from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.ws13_determinism_envelope_validate import (  # noqa: E402
    CI_DIR_REL,
    CI_KEYLESS_BUNDLE_REL,
    CI_KEYLESS_RECEIPT_REL,
    CI_TRUTH_DIAGNOSTIC_REL,
    CLASS_POLICY_REL,
    ENVELOPE_POLICY_REL,
    EXECUTION_DAG_REL,
    LOCAL_DIR_REL,
    PROBE_FILENAME,
    PUBLIC_VERIFIER_MANIFEST_REL,
    RECEIPT_REL,
    SIGNER_IDENTITY_POLICY_REL,
    SIGNER_TOPOLOGY_REL,
    TRUST_ROOT_POLICY_REL,
    WS12_RECEIPT_REL,
    emit_environment_bundle,
    emit_ws13_determinism_envelope,
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


def _truth_index(*, head: str, dirty: bool, pass_state: bool = True) -> dict:
    return {
        "checks": [
            {
                "check_id": "current_worktree_cleanroom_suite",
                "critical": True,
                "scope": "active_repo_validation",
                "status": "PASS" if pass_state else "FAIL",
                "summary": "current-worktree cleanroom suite passed" if pass_state else "current-worktree cleanroom suite failed",
            }
        ],
        "schema_id": "kt.operator.live_validation_index.v1",
        "worktree": {"git_dirty": dirty, "head_sha": head},
    }


def _set_ws13_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYTHONHASHSEED", "0")
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    monkeypatch.setenv("TZ", "UTC")
    monkeypatch.setenv("LANG", "C.UTF-8")
    monkeypatch.setenv("LC_ALL", "C.UTF-8")
    monkeypatch.setenv("PYTHONIOENCODING", "UTF-8")
    monkeypatch.setenv("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")


def _seed_ws13_repo(tmp_path: Path) -> str:
    _init_git_repo(tmp_path)
    (tmp_path / "README.md").write_text("base\n", encoding="utf-8")
    _commit_all(tmp_path, "seed base")
    _write_json(
        tmp_path / EXECUTION_DAG_REL,
        {
            "current_node": "WS13_ARTIFACT_CLASS_AND_DETERMINISM_ENVELOPE_LOCK",
            "current_repo_head": "PLACEHOLDER",
            "dag_id": "KT_SOVEREIGN_EXECUTION_DAG_V1_20260317",
            "generated_utc": "2026-03-18T00:00:00Z",
            "next_lawful_workstream": "WS13_ARTIFACT_CLASS_AND_DETERMINISM_ENVELOPE_LOCK",
            "nodes": [
                {"id": "WS12_IN_TOTO_SLSA_AND_TUF_ATTACK_COVERAGE", "status": "PASS"},
                {"id": "WS13_ARTIFACT_CLASS_AND_DETERMINISM_ENVELOPE_LOCK", "status": "UNLOCKED", "ratification_checkpoint": "kt_determinism_envelope_receipt.json"},
                {"id": "WS14_STATIC_VERIFIER_RELEASE_AND_ACCEPTANCE_POLICY", "status": "LOCKED_PENDING_WS13_PASS"},
            ],
            "schema_id": "kt.governance.execution_dag.v1",
            "semantic_boundary": {"lawful_current_claim": "seed"},
            "status": "ACTIVE",
        },
    )
    _write_json(
        tmp_path / TRUST_ROOT_POLICY_REL,
        {
            "closure_boundary": {"next_required_step": "WS13_ARTIFACT_CLASS_AND_DETERMINISM_ENVELOPE_LOCK"},
            "current_repo_head": "PLACEHOLDER",
            "generated_utc": "2026-03-18T00:00:00Z",
            "schema_id": "kt.governance.trust_root_policy.v1",
            "semantic_boundary": {"lawful_current_claim": "seed"},
        },
    )
    _write_json(
        tmp_path / SIGNER_TOPOLOGY_REL,
        {
            "current_repo_head": "PLACEHOLDER",
            "generated_utc": "2026-03-18T00:00:00Z",
            "schema_id": "kt.governance.signer_topology.v1",
            "semantic_boundary": {"lawful_current_claim": "seed"},
        },
    )
    _write_json(
        tmp_path / SIGNER_IDENTITY_POLICY_REL,
        {
            "keyless_constraints": {
                "certificate_identity": "https://github.com/Kinrokin/KT/.github/workflows/ci_truth_barrier.yml@refs/heads/main",
                "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
            },
            "schema_id": "kt.governance.signer_identity_policy.v1",
        },
    )
    _write_json(tmp_path / WS12_RECEIPT_REL, {"status": "PASS"})
    _write_json(
        tmp_path / CLASS_POLICY_REL,
        {
            "classes": [
                {
                    "class_id": "CLASS_A",
                    "surfaces": [
                        {"path": CLASS_POLICY_REL, "surface_id": "artifact_class_policy"},
                        {"path": ENVELOPE_POLICY_REL, "surface_id": "determinism_envelope_policy"},
                        {"path": PUBLIC_VERIFIER_MANIFEST_REL, "surface_id": "bounded_public_verifier_manifest"},
                    ],
                },
                {
                    "canonicalization_profile_id": "live_validation_index_v1",
                    "class_id": "CLASS_B",
                    "surfaces": [{"path_role": "environment_bundle/live_validation_index", "surface_id": "current_truth_barrier_live_validation_index"}],
                },
                {
                    "class_id": "CLASS_C",
                    "surfaces": [
                        {"path": CI_TRUTH_DIAGNOSTIC_REL, "surface_id": "current_truth_barrier_remote_diagnostic"},
                        {"path": CI_KEYLESS_RECEIPT_REL, "surface_id": "current_keyless_execution_receipt"},
                        {"path": CI_KEYLESS_BUNDLE_REL, "surface_id": "current_keyless_sigstore_bundle"},
                    ],
                },
            ],
            "schema_id": "kt.governance.artifact_class_policy.v1",
            "status": "ACTIVE",
        },
    )
    _write_json(
        tmp_path / ENVELOPE_POLICY_REL,
        {
            "class_b_canonicalization_profiles": [{"profile_id": "live_validation_index_v1"}],
            "deterministic_emitter_dependency_model": {"mode": "PYTHON_STDLIB_ONLY"},
            "forbidden_drift": ["unordered directory walks"],
            "normalization_rules": {"path_separator": "POSIX_SLASH"},
            "required_environment_variables": {
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                "PYTHONHASHSEED": "0",
                "PYTHONIOENCODING": "UTF-8",
                "SOURCE_DATE_EPOCH": "1700000000",
                "TZ": "UTC",
            },
            "schema_id": "kt.governance.determinism_envelope_policy.v1",
            "supported_environment_classes": [
                {
                    "environment_class": "local_windows",
                    "environment_provenance": "local_user_managed",
                    "platform_prefix": "Windows-10-10.0.26200-SP0",
                    "python_major_minor": "3.10",
                },
                {
                    "environment_class": "github_actions_ubuntu",
                    "environment_provenance": "github_actions",
                    "platform_prefix": "Linux",
                    "python_major_minor": "3.11",
                },
            ],
            "truth_barrier_dependency_pins": {"jsonschema": "4.25.1", "pytest": "9.0.2", "pyyaml": "6.0.3"},
        },
    )
    _write_json(tmp_path / PUBLIC_VERIFIER_MANIFEST_REL, {"status": "PASS"})
    subject_head = _commit_all(tmp_path, "seed ws13 inputs")

    dag = json.loads((tmp_path / EXECUTION_DAG_REL).read_text(encoding="utf-8"))
    dag["current_repo_head"] = subject_head
    _write_json(tmp_path / EXECUTION_DAG_REL, dag)
    for rel in (TRUST_ROOT_POLICY_REL, SIGNER_TOPOLOGY_REL):
        payload = json.loads((tmp_path / rel).read_text(encoding="utf-8"))
        payload["current_repo_head"] = subject_head
        _write_json(tmp_path / rel, payload)

    _write_json(tmp_path / f"{LOCAL_DIR_REL}/live_validation_index.local.json", _truth_index(head=subject_head, dirty=False, pass_state=True))
    _write_json(tmp_path / f"{CI_DIR_REL}/live_validation_index.ci.json", _truth_index(head=subject_head, dirty=False, pass_state=True))
    _write_json(
        tmp_path / CI_TRUTH_DIAGNOSTIC_REL,
        {
            "branch_ref": "refs/heads/main",
            "run_id": "run-1",
            "schema_id": "kt.operator.truth_barrier_remote_diagnostic.v1",
            "status": "PASS",
            "truth_barrier_step_outcome": "success",
        },
    )
    bundle_path = tmp_path / CI_KEYLESS_BUNDLE_REL
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    bundle_path.write_text("{\"bundle\":\"ok\"}\n", encoding="utf-8")
    manifest_sha = hashlib.sha256((tmp_path / PUBLIC_VERIFIER_MANIFEST_REL).read_bytes()).hexdigest()
    bundle_sha = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
    _write_json(
        tmp_path / CI_KEYLESS_RECEIPT_REL,
        {
            "branch_ref": "refs/heads/main",
            "bundle_path": CI_KEYLESS_BUNDLE_REL,
            "bundle_sha256": bundle_sha,
            "certificate_identity": "https://github.com/Kinrokin/KT/.github/workflows/ci_truth_barrier.yml@refs/heads/main",
            "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
            "executed_signer_mode": "sigstore_keyless",
            "run_id": "run-1",
            "signed_surface_path": PUBLIC_VERIFIER_MANIFEST_REL,
            "signed_surface_sha256": manifest_sha,
            "status": "PASS",
            "verification_status": "PASS",
        },
    )
    return subject_head


def _rewrite_probe(path: Path, *, platform_value: str, python_major_minor: str, python_version: str) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["platform"] = platform_value
    payload["python_major_minor"] = python_major_minor
    payload["python_version"] = python_version
    _write_json(path, payload)


def test_emit_ws13_pass_when_local_and_ci_subject_sets_match(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    subject_head = _seed_ws13_repo(tmp_path)
    _set_ws13_env(monkeypatch)
    emit_environment_bundle(
        root=tmp_path,
        out_dir_rel=LOCAL_DIR_REL,
        environment_id="local_windows_py310",
        environment_class="local_windows",
        environment_provenance="local_user_managed",
        live_validation_index_rel=f"{LOCAL_DIR_REL}/live_validation_index.local.json",
    )
    _rewrite_probe(
        tmp_path / LOCAL_DIR_REL / PROBE_FILENAME,
        platform_value="Windows-10-10.0.26200-SP0",
        python_major_minor="3.10",
        python_version="3.10.11",
    )
    emit_environment_bundle(
        root=tmp_path,
        out_dir_rel=CI_DIR_REL,
        environment_id="github_actions_ubuntu_py311",
        environment_class="github_actions_ubuntu",
        environment_provenance="github_actions",
        live_validation_index_rel=f"{CI_DIR_REL}/live_validation_index.ci.json",
    )
    _rewrite_probe(
        tmp_path / CI_DIR_REL / PROBE_FILENAME,
        platform_value="Linux-6.8.0-github-actions",
        python_major_minor="3.11",
        python_version="3.11.11",
    )

    receipt = emit_ws13_determinism_envelope(root=tmp_path)
    assert receipt["status"] == "PASS"
    assert receipt["blocked_by"] == []
    assert receipt["compiled_against"] == subject_head
    dag = json.loads((tmp_path / EXECUTION_DAG_REL).read_text(encoding="utf-8"))
    ws13 = next(row for row in dag["nodes"] if row["id"] == "WS13_ARTIFACT_CLASS_AND_DETERMINISM_ENVELOPE_LOCK")
    ws14 = next(row for row in dag["nodes"] if row["id"] == "WS14_STATIC_VERIFIER_RELEASE_AND_ACCEPTANCE_POLICY")
    assert ws13["status"] == "PASS"
    assert ws14["status"] == "UNLOCKED"
    assert (tmp_path / RECEIPT_REL).exists()


def test_emit_ws13_partial_when_class_b_canonical_hashes_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_ws13_repo(tmp_path)
    _set_ws13_env(monkeypatch)
    emit_environment_bundle(
        root=tmp_path,
        out_dir_rel=LOCAL_DIR_REL,
        environment_id="local_windows_py310",
        environment_class="local_windows",
        environment_provenance="local_user_managed",
        live_validation_index_rel=f"{LOCAL_DIR_REL}/live_validation_index.local.json",
    )
    _rewrite_probe(
        tmp_path / LOCAL_DIR_REL / PROBE_FILENAME,
        platform_value="Windows-10-10.0.26200-SP0",
        python_major_minor="3.10",
        python_version="3.10.11",
    )
    ci_index = json.loads((tmp_path / f"{CI_DIR_REL}/live_validation_index.ci.json").read_text(encoding="utf-8"))
    ci_index["checks"][0]["summary"] = "different summary"
    _write_json(tmp_path / f"{CI_DIR_REL}/live_validation_index.ci.json", ci_index)
    emit_environment_bundle(
        root=tmp_path,
        out_dir_rel=CI_DIR_REL,
        environment_id="github_actions_ubuntu_py311",
        environment_class="github_actions_ubuntu",
        environment_provenance="github_actions",
        live_validation_index_rel=f"{CI_DIR_REL}/live_validation_index.ci.json",
    )
    _rewrite_probe(
        tmp_path / CI_DIR_REL / PROBE_FILENAME,
        platform_value="Linux-6.8.0-github-actions",
        python_major_minor="3.11",
        python_version="3.11.11",
    )

    receipt = emit_ws13_determinism_envelope(root=tmp_path)
    assert receipt["status"] == "PARTIAL"
    assert "SUBJECT_SET_HASH_MISMATCH" in receipt["blocked_by"]
    assert "CLASS_B_CANONICAL_HASH_MISMATCH" in receipt["blocked_by"]


def test_emit_ws13_fails_closed_when_required_ci_bundle_is_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_ws13_repo(tmp_path)
    _set_ws13_env(monkeypatch)
    emit_environment_bundle(
        root=tmp_path,
        out_dir_rel=LOCAL_DIR_REL,
        environment_id="local_windows_py310",
        environment_class="local_windows",
        environment_provenance="local_user_managed",
        live_validation_index_rel=f"{LOCAL_DIR_REL}/live_validation_index.local.json",
    )
    _rewrite_probe(
        tmp_path / LOCAL_DIR_REL / PROBE_FILENAME,
        platform_value="Windows-10-10.0.26200-SP0",
        python_major_minor="3.10",
        python_version="3.10.11",
    )
    with pytest.raises(RuntimeError, match="missing required WS13 input"):
        emit_ws13_determinism_envelope(root=tmp_path)
