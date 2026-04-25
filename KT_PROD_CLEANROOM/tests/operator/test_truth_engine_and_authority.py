from __future__ import annotations

import json
import subprocess
from pathlib import Path

from tools.operator.truth_authority import (
    build_settled_truth_source_receipt,
    resolve_truth_head_context,
    split_publication_carrier_dirty_paths,
)
from tools.operator.truth_engine import build_truth_receipts


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_call(root: Path, *args: str) -> None:
    subprocess.check_call(["git", "-C", str(root), *args])


def _seed_truth_root(root: Path) -> None:
    _write_json(
        root / "KT_PROD_CLEANROOM" / "reports" / "current_state_receipt.json",
        {
            "schema_id": "kt.operator.current_state_receipt.v3",
            "posture_state": "CANONICAL_READY_FOR_REEARNED_GREEN",
            "current_p0_state": "CANONICAL_READY_FOR_REEARNED_GREEN",
            "branch_ref": "ops/test",
            "validated_head_sha": "abc123",
            "status": "PASS",
        },
    )
    _write_json(
        root / "KT_PROD_CLEANROOM" / "reports" / "runtime_closure_audit.json",
        {
            "schema_id": "kt.operator.runtime_closure_audit.v3",
            "posture_state": "CANONICAL_READY_FOR_REEARNED_GREEN",
            "current_state": "CANONICAL_READY_FOR_REEARNED_GREEN",
            "branch_ref": "ops/test",
            "validated_head_sha": "abc123",
            "status": "PASS",
        },
    )
    _write_json(
        root / "KT_PROD_CLEANROOM" / "reports" / "posture_consistency_receipt.json",
        {
            "schema_id": "kt.operator.posture_consistency_receipt.v1",
            "status": "PASS",
            "posture_state": "CANONICAL_READY_FOR_REEARNED_GREEN",
            "validated_head_sha": "abc123",
        },
    )
    _write_json(
        root / "KT_PROD_CLEANROOM" / "governance" / "posture_contract.json",
        {
            "schema_id": "kt.governance.posture_contract.v1",
            "contract_id": "POSTURE_CONTRACT_TEST",
        },
    )
    _write_json(
        root / "KT_PROD_CLEANROOM" / "governance" / "truth_engine_contract.json",
        {
            "schema_id": "kt.governance.truth_engine_contract.v2",
            "contract_id": "TRUTH_ENGINE_CONTRACT_TEST",
        },
    )


def test_truth_engine_accepts_external_live_validation_index(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    external_root = tmp_path / "external"
    _seed_truth_root(repo_root)
    external_index = external_root / "live_validation_index.json"
    _write_json(
        external_index,
        {
            "schema_id": "kt.operator.live_validation_index.v1",
            "branch_ref": "ops/test",
            "worktree": {"git_dirty": False, "head_sha": "abc123", "dirty_files": []},
            "checks": [
                {"check_id": "constitutional_guard", "critical": True, "dirty_sensitive": False, "status": "PASS"},
                {"check_id": "operator_clean_clone_smoke", "critical": True, "dirty_sensitive": False, "status": "PASS"},
            ],
        },
    )

    receipts = build_truth_receipts(root=repo_root, live_validation_index_path=external_index, report_root_rel="KT_PROD_CLEANROOM/reports")

    assert receipts["enforcement"]["status"] == "PASS"
    assert receipts["enforcement"]["validation_index_ref"] == external_index.resolve().as_posix()


def test_settled_truth_receipt_becomes_settled_when_clean_clone_and_receipts_pass(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    external_index = repo_root / "tmp" / "live_validation_index.json"
    _seed_truth_root(repo_root)
    _write_json(
        external_index,
        {
            "schema_id": "kt.operator.live_validation_index.v1",
            "branch_ref": "ops/test",
            "worktree": {"git_dirty": False, "head_sha": "abc123", "dirty_files": []},
            "checks": [
                {"check_id": "constitutional_guard", "critical": True, "dirty_sensitive": False, "status": "PASS"},
                {"check_id": "operator_clean_clone_smoke", "critical": True, "dirty_sensitive": False, "status": "PASS"},
            ],
        },
    )

    truth_receipts = build_truth_receipts(root=repo_root, live_validation_index_path=external_index, report_root_rel="KT_PROD_CLEANROOM/reports")
    current_state = json.loads((repo_root / "KT_PROD_CLEANROOM" / "reports" / "current_state_receipt.json").read_text(encoding="utf-8"))
    runtime_audit = json.loads((repo_root / "KT_PROD_CLEANROOM" / "reports" / "runtime_closure_audit.json").read_text(encoding="utf-8"))
    posture = json.loads((repo_root / "KT_PROD_CLEANROOM" / "reports" / "posture_consistency_receipt.json").read_text(encoding="utf-8"))
    index = json.loads(external_index.read_text(encoding="utf-8"))

    receipt = build_settled_truth_source_receipt(
        root=repo_root,
        live_validation_index_path=external_index,
        report_root_rel="KT_PROD_CLEANROOM/reports",
        index=index,
        current_state=current_state,
        runtime_audit=runtime_audit,
        posture_consistency=posture,
        enforcement=truth_receipts["enforcement"],
        conflicts=truth_receipts["conflicts"],
    )

    assert receipt["status"] == "SETTLED_AUTHORITATIVE"
    assert receipt["current_head_truth_source"] == "tmp/live_validation_index.json"
    assert receipt["authoritative_current_pointer_ref"] == "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json"


def test_truth_engine_accepts_publication_carrier_dirty_without_downgrading_subject(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    external_index = repo_root / "tmp" / "live_validation_index.json"
    _seed_truth_root(repo_root)
    _write_json(
        repo_root / "KT_PROD_CLEANROOM" / "reports" / "current_state_receipt.json",
        {
            "schema_id": "kt.operator.current_state_receipt.v3",
            "posture_state": "CANONICAL_READY_FOR_REEARNED_GREEN",
            "current_p0_state": "CANONICAL_READY_FOR_REEARNED_GREEN",
            "branch_ref": "main",
            "validated_head_sha": "abc123",
            "publication_carrier_head_sha": "def456",
            "status": "PASS",
        },
    )
    _write_json(
        repo_root / "KT_PROD_CLEANROOM" / "reports" / "runtime_closure_audit.json",
        {
            "schema_id": "kt.operator.runtime_closure_audit.v3",
            "posture_state": "CANONICAL_READY_FOR_REEARNED_GREEN",
            "current_state": "CANONICAL_READY_FOR_REEARNED_GREEN",
            "branch_ref": "main",
            "validated_head_sha": "abc123",
            "publication_carrier_head_sha": "def456",
            "status": "PASS",
        },
    )
    _write_json(
        repo_root / "KT_PROD_CLEANROOM" / "reports" / "posture_consistency_receipt.json",
        {
            "schema_id": "kt.operator.posture_consistency_receipt.v1",
            "status": "PASS",
            "posture_state": "CANONICAL_READY_FOR_REEARNED_GREEN",
            "validated_head_sha": "abc123",
        },
    )
    _write_json(
        external_index,
        {
            "schema_id": "kt.operator.live_validation_index.v1",
            "branch_ref": "main",
            "worktree": {
                "git_dirty": True,
                "subject_git_dirty": False,
                "publication_carrier_dirty": True,
                "head_sha": "def456",
                "validated_subject_head_sha": "abc123",
                "publication_carrier_head_sha": "def456",
                "head_relation": "PUBLICATION_CARRIER_OF_VALIDATED_SUBJECT",
                "dirty_files": ["M KT_PROD_CLEANROOM/reports/current_state_receipt.json"],
                "subject_dirty_files": [],
                "publication_carrier_dirty_files": ["KT_PROD_CLEANROOM/reports/current_state_receipt.json"],
            },
            "checks": [
                {"check_id": "constitutional_guard", "critical": True, "dirty_sensitive": False, "status": "PASS"},
                {"check_id": "operator_clean_clone_smoke", "critical": True, "dirty_sensitive": False, "status": "PASS"},
                {"check_id": "current_worktree_cleanroom_suite", "critical": True, "dirty_sensitive": True, "status": "FAIL"},
            ],
        },
    )

    truth_receipts = build_truth_receipts(root=repo_root, live_validation_index_path=external_index, report_root_rel="KT_PROD_CLEANROOM/reports")
    current_state = json.loads((repo_root / "KT_PROD_CLEANROOM" / "reports" / "current_state_receipt.json").read_text(encoding="utf-8"))
    runtime_audit = json.loads((repo_root / "KT_PROD_CLEANROOM" / "reports" / "runtime_closure_audit.json").read_text(encoding="utf-8"))
    posture = json.loads((repo_root / "KT_PROD_CLEANROOM" / "reports" / "posture_consistency_receipt.json").read_text(encoding="utf-8"))
    index = json.loads(external_index.read_text(encoding="utf-8"))

    assert truth_receipts["enforcement"]["status"] == "PASS"
    assert truth_receipts["enforcement"]["derived_state"] == "CANONICAL_READY_FOR_REEARNED_GREEN"
    assert truth_receipts["enforcement"]["validated_subject_head_sha"] == "abc123"
    assert truth_receipts["enforcement"]["publication_carrier_head_sha"] == "def456"

    receipt = build_settled_truth_source_receipt(
        root=repo_root,
        live_validation_index_path=external_index,
        report_root_rel="KT_PROD_CLEANROOM/reports",
        index=index,
        current_state=current_state,
        runtime_audit=runtime_audit,
        posture_consistency=posture,
        enforcement=truth_receipts["enforcement"],
        conflicts=truth_receipts["conflicts"],
    )

    assert receipt["status"] == "SETTLED_AUTHORITATIVE"
    assert receipt["pinned_head_sha"] == "abc123"
    assert receipt["publication_carrier_head_sha"] == "def456"
    assert "WORKTREE_DIRTY" not in receipt["open_blockers"]


def test_resolve_truth_head_context_preserves_prior_subject_for_carrier_only_commit(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir(parents=True, exist_ok=True)
    _git_call(root, "init", "-b", "main")
    _git_call(root, "config", "user.email", "test@example.com")
    _git_call(root, "config", "user.name", "Test User")

    _write_json(
        root / "KT_PROD_CLEANROOM" / "governance" / "documentary_truth_policy.json",
        {
            "schema_id": "kt.governance.documentary_truth_policy.v1",
            "active_current_head_truth_source": "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
        },
    )
    _write_json(
        root / "KT_PROD_CLEANROOM" / "governance" / "truth_publication_cleanliness_rules.json",
        {
            "schema_id": "kt.governance.truth_publication_cleanliness_rules.v1",
            "allowed_publication_carrier_surfaces": [
                "KT_PROD_CLEANROOM/reports/**",
                "KT_PROD_CLEANROOM/exports/_truth/current/**",
                "KT_PROD_CLEANROOM/governance/execution_board.json",
            ],
        },
    )
    (root / "README.md").write_text("subject\n", encoding="utf-8")
    _git_call(root, "add", ".")
    _git_call(root, "commit", "-m", "subject")
    subject_head = _git(root, "rev-parse", "HEAD")

    _write_json(
        root / "KT_PROD_CLEANROOM" / "exports" / "_truth" / "current" / "current_pointer.json",
        {
            "schema_id": "kt.operator.truth_pointer.v1",
            "truth_subject_commit": subject_head,
            "truth_produced_at_commit": subject_head,
        },
    )
    _write_json(
        root / "KT_PROD_CLEANROOM" / "reports" / "current_state_receipt.json",
        {"schema_id": "kt.operator.current_state_receipt.v3", "validated_head_sha": subject_head},
    )
    _git_call(root, "add", ".")
    _git_call(root, "commit", "-m", "publish documentary carrier")
    carrier_head = _git(root, "rev-parse", "HEAD")

    context = resolve_truth_head_context(
        root=root,
        live_head=carrier_head,
        dirty_lines=["M KT_PROD_CLEANROOM/reports/current_state_receipt.json"],
    )

    assert context["validated_subject_head_sha"] == subject_head
    assert context["publication_carrier_head_sha"] == carrier_head
    assert context["head_relation"] == "PUBLICATION_CARRIER_OF_VALIDATED_SUBJECT"


def test_split_publication_carrier_dirty_paths_normalizes_short_status_prefixes(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _write_json(
        root / "KT_PROD_CLEANROOM" / "governance" / "truth_publication_cleanliness_rules.json",
        {
            "schema_id": "kt.governance.truth_publication_cleanliness_rules.v1",
            "allowed_publication_carrier_surfaces": [
                "KT_PROD_CLEANROOM/reports/**",
                "KT_PROD_CLEANROOM/exports/_truth/current/**",
            ],
        },
    )

    split = split_publication_carrier_dirty_paths(
        root=root,
        dirty_lines=[
            "M KT_PROD_CLEANROOM/reports/current_state_receipt.json",
            " M KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
        ],
    )

    assert split["subject_git_dirty"] is False
    assert split["publication_carrier_only_dirty"] is True
    assert split["subject_dirty_files"] == []
    assert split["publication_carrier_dirty_files"] == [
        "KT_PROD_CLEANROOM/reports/current_state_receipt.json",
        "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
    ]
