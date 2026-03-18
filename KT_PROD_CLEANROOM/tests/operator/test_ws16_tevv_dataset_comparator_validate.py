from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.ws16_tevv_dataset_comparator_validate import (  # noqa: E402
    BENCHMARK_VALIDITY_WINDOWS_REL,
    CI_KEYLESS_RECEIPT_REL,
    CI_LIVE_INDEX_REL,
    CI_REMOTE_DIAGNOSTIC_REL,
    CI_SIGNED_SURFACE_REL,
    CI_SIGSTORE_BUNDLE_REL,
    CI_SUBJECT_SET_REL,
    CLAIM_COMPILER_REL,
    COMPARATOR_REGISTRY_REL,
    DATASET_PIN_REGISTRY_REL,
    DETERMINISM_POLICY_REL,
    EXECUTION_DAG_REL,
    LOCAL_LIVE_INDEX_REL,
    LOCAL_SUBJECT_SET_REL,
    NEXT_WORKSTREAM_ID,
    RECEIPT_REL,
    REPLAY_RECIPE_REL,
    TEVV_PACK_MANIFEST_REL,
    TEVV_PACK_POLICY_REL,
    TRUST_ASSUMPTIONS_REL,
    TRUTH_ASSUMPTIONS_REL,
    TRUTH_FRESHNESS_WINDOWS_REL,
    WORKSTREAM_ID,
    WS13_RECEIPT_REL,
    WS14_RECEIPT_REL,
    WS15_RECEIPT_REL,
    emit_ws16_tevv_dataset_registry,
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


def _now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _seed_ws16_repo(tmp_path: Path) -> str:
    _init_git_repo(tmp_path)
    (tmp_path / "README.md").write_text("seed\n", encoding="utf-8")
    _commit_all(tmp_path, "seed base")

    subject_head = "a2cc7ba323cf143def4133d722a7e79dbf35729b"
    signed_surface = {"schema_id": "kt.operator.public_verifier_manifest.v4", "subject_head_commit": subject_head}
    bundle = {"schema_id": "sigstore.bundle.v1", "artifact": "public_verifier_manifest.json"}

    _write_json(
        tmp_path / EXECUTION_DAG_REL,
        {
            "current_node": WORKSTREAM_ID,
            "current_repo_head": "PLACEHOLDER",
            "dag_id": "KT_SOVEREIGN_EXECUTION_DAG_V1_20260317",
            "generated_utc": _now_z(),
            "next_lawful_workstream": WORKSTREAM_ID,
            "nodes": [
                {"id": WORKSTREAM_ID, "ratification_checkpoint": "kt_tevv_dataset_registry_receipt.json", "status": "UNLOCKED"},
                {"id": "WS17A_EXTERNAL_CONFIRMATION_ASSURANCE", "ratification_checkpoint": "external_assurance_receipt", "status": "LOCKED_PENDING_WS16_PASS"},
                {"id": "WS17B_EXTERNAL_CONFIRMATION_CAPABILITY", "ratification_checkpoint": "external_capability_receipt", "status": "LOCKED_PENDING_WS16_PASS"},
            ],
            "schema_id": "kt.governance.execution_dag.v1",
            "semantic_boundary": {"lawful_current_claim": "seed", "stronger_claim_not_made": []},
            "status": "ACTIVE",
        },
    )
    _write_json(tmp_path / WS13_RECEIPT_REL, {"schema_id": "kt.operator.ws13.determinism_envelope_receipt.v1", "status": "PASS", "compiled_against": subject_head, "current_repo_head": subject_head})
    _write_json(tmp_path / WS14_RECEIPT_REL, {"schema_id": "kt.operator.public_verifier_release_receipt.v1", "status": "PASS", "compiled_against": subject_head, "current_repo_head": subject_head})
    _write_json(tmp_path / CLAIM_COMPILER_REL, {"schema_id": "kt.operator.claim_proof_ceiling_compiler.v1", "blocked_current_claim_ids": ["threshold_root_verifier_acceptance_active", "release_readiness_proven", "campaign_completion_proven"]})
    _write_json(tmp_path / DETERMINISM_POLICY_REL, {"schema_id": "kt.governance.determinism_envelope_policy.v1", "class_b_canonicalization_profiles": [{"profile_id": "live_validation_index_v1"}]})
    _write_json(tmp_path / TRUTH_FRESHNESS_WINDOWS_REL, {"schema_id": "kt.governance.truth_freshness_windows.v1", "freshness_windows_hours": {"live_validation_index": 24}, "staleness_is_fail_closed": True})
    _write_json(tmp_path / LOCAL_LIVE_INDEX_REL, {"schema_id": "kt.operator.live_validation_index.v1", "generated_utc": _now_z(), "worktree": {"head_sha": subject_head, "git_dirty": False}, "checks": []})
    _write_json(tmp_path / CI_LIVE_INDEX_REL, {"schema_id": "kt.operator.live_validation_index.v1", "generated_utc": _now_z(), "worktree": {"head_sha": subject_head, "git_dirty": False}, "checks": []})
    _write_json(tmp_path / LOCAL_SUBJECT_SET_REL, {"schema_id": "kt.operator.ws13.determinism_subject_set.v1", "subject_head_commit": subject_head})
    _write_json(tmp_path / CI_SUBJECT_SET_REL, {"schema_id": "kt.operator.ws13.determinism_subject_set.v1", "subject_head_commit": subject_head})
    _write_json(tmp_path / CI_SIGNED_SURFACE_REL, signed_surface)
    _write_json(tmp_path / CI_SIGSTORE_BUNDLE_REL, bundle)
    signed_surface_sha = hashlib.sha256((tmp_path / CI_SIGNED_SURFACE_REL).read_bytes()).hexdigest()
    bundle_sha = hashlib.sha256((tmp_path / CI_SIGSTORE_BUNDLE_REL).read_bytes()).hexdigest()
    _write_json(
        tmp_path / CI_KEYLESS_RECEIPT_REL,
        {
            "schema_id": "kt.operator.ws11_keyless_execution_receipt.v1",
            "status": "PASS",
            "run_id": "23229317266",
            "executed_signer_mode": "sigstore_keyless",
            "signed_surface_sha256": signed_surface_sha,
            "bundle_sha256": bundle_sha,
            "keyless_backed_surfaces": ["KT_PROD_CLEANROOM/reports/public_verifier_manifest.json"],
        },
    )
    _write_json(
        tmp_path / CI_REMOTE_DIAGNOSTIC_REL,
        {
            "schema_id": "kt.operator.truth_barrier_remote_diagnostic.v1",
            "status": "PASS",
            "run_id": "23229317266",
            "truth_barrier_step_outcome": "success",
        },
    )
    (tmp_path / REPLAY_RECIPE_REL).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / REPLAY_RECIPE_REL).write_text("# recipe\n", encoding="utf-8")

    freeze_head = _commit_all(tmp_path, "freeze ws15 boundary")
    _write_json(tmp_path / WS15_RECEIPT_REL, {"schema_id": "kt.operator.claim_abi_receipt.v1", "status": "PASS", "compiled_against": freeze_head})
    _write_json(tmp_path / EXECUTION_DAG_REL, {**json.loads((tmp_path / EXECUTION_DAG_REL).read_text(encoding="utf-8")), "current_repo_head": freeze_head})
    _commit_all(tmp_path, "add ws15 receipt")
    return _git(tmp_path, "rev-parse", "HEAD")


def test_emit_ws16_pass_locks_pins_and_unlocks_ws17(tmp_path: Path) -> None:
    freeze_head = _seed_ws16_repo(tmp_path)

    receipt = emit_ws16_tevv_dataset_registry(root=tmp_path)

    assert receipt["status"] == "PASS"
    assert receipt["compiled_against"] == freeze_head
    assert receipt["next_lawful_workstream"] == NEXT_WORKSTREAM_ID
    dag = json.loads((tmp_path / EXECUTION_DAG_REL).read_text(encoding="utf-8"))
    ws16 = next(row for row in dag["nodes"] if row["id"] == WORKSTREAM_ID)
    ws17a = next(row for row in dag["nodes"] if row["id"] == NEXT_WORKSTREAM_ID)
    assert ws16["status"] == "PASS"
    assert ws17a["status"] == "UNLOCKED"
    assert (tmp_path / TRUST_ASSUMPTIONS_REL).exists()
    assert (tmp_path / TEVV_PACK_POLICY_REL).exists()
    assert (tmp_path / DATASET_PIN_REGISTRY_REL).exists()
    assert (tmp_path / COMPARATOR_REGISTRY_REL).exists()
    assert (tmp_path / BENCHMARK_VALIDITY_WINDOWS_REL).exists()
    assert (tmp_path / TEVV_PACK_MANIFEST_REL).exists()
    assert (tmp_path / RECEIPT_REL).exists()


def test_emit_ws16_partial_when_subject_heads_diverge(tmp_path: Path) -> None:
    _seed_ws16_repo(tmp_path)
    _write_json(tmp_path / CI_SUBJECT_SET_REL, {"schema_id": "kt.operator.ws13.determinism_subject_set.v1", "subject_head_commit": "DIFFERENT"})
    _commit_all(tmp_path, "diverge ci subject set")

    receipt = emit_ws16_tevv_dataset_registry(root=tmp_path)

    assert receipt["status"] == "PARTIAL"
    assert "UPSTREAM_TEVV_SUBJECT_HEAD_DIVERGENCE" in receipt["blocked_by"]


def test_emit_ws16_fails_closed_when_repo_is_not_frozen(tmp_path: Path) -> None:
    _seed_ws16_repo(tmp_path)
    (tmp_path / "scratch.txt").write_text("dirty\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="WS16 requires a frozen repo except for the bounded WS16 write set"):
        emit_ws16_tevv_dataset_registry(root=tmp_path)
