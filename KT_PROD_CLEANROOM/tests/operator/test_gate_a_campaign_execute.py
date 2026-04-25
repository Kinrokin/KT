from __future__ import annotations

import json
import subprocess
from pathlib import Path

from tools.operator.gate_a_campaign_execute import (
    GOVERNANCE_AUTHORITY_SUPERSESSION_REGISTRY_REL,
    build_authority_supersession_registry,
    build_clean_current_head_receipt,
    build_truth_lock_freshness_receipt,
)
from tools.operator.titanium_common import repo_root


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, encoding="utf-8").strip()


def _init_repo(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test User")


def test_truth_lock_freshness_receipt_passes_and_fails(tmp_path: Path) -> None:
    expected = {"schema_id": "test.lock", "status": "PASS", "value": "fresh"}
    lock_path = tmp_path / "KT_PROD_CLEANROOM" / "governance" / "current_head_truth_lock.json"
    _write_json(lock_path, expected)

    passing = build_truth_lock_freshness_receipt(root=tmp_path, expected_lock=expected)
    assert passing["status"] == "PASS"
    assert passing["semantically_fresh"] is True

    _write_json(lock_path, {"schema_id": "test.lock", "status": "PASS", "value": "stale"})
    failing = build_truth_lock_freshness_receipt(root=tmp_path, expected_lock=expected)
    assert failing["status"] == "FAIL_CLOSED"
    assert failing["semantically_fresh"] is False


def test_clean_current_head_receipt_detects_missing_refs(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    tracked_rel = "KT_PROD_CLEANROOM/governance/current_head_truth_lock.json"
    _write_json(tmp_path / tracked_rel, {"status": "PASS"})
    _git(tmp_path, "add", tracked_rel)
    _git(tmp_path, "commit", "-m", "seed tracked authority surface")

    passing = build_clean_current_head_receipt(root=tmp_path, required_refs=[tracked_rel])
    assert passing["status"] == "PASS"
    assert passing["missing_from_clean_head_snapshot"] == []

    failing = build_clean_current_head_receipt(
        root=tmp_path,
        required_refs=[tracked_rel, "KT_PROD_CLEANROOM/reports/missing_receipt.json"],
    )
    assert failing["status"] == "FAIL_CLOSED"
    assert "KT_PROD_CLEANROOM/reports/missing_receipt.json" in failing["missing_from_clean_head_snapshot"]


def test_clean_current_head_receipt_accepts_sealed_worktree_scope(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    tracked_rel = "KT_PROD_CLEANROOM/governance/execution_board.json"
    _write_json(tmp_path / tracked_rel, {"status": "PASS"})
    _git(tmp_path, "add", tracked_rel)
    _git(tmp_path, "commit", "-m", "seed tracked authority surface")

    live_only_rel = "KT_PROD_CLEANROOM/governance/current_head_truth_lock.json"
    _write_json(tmp_path / live_only_rel, {"status": "PASS"})
    lock = {
        "status": "PASS",
        "active_authority_mode": "WORKTREE_TRANSITIONAL_CURRENT_HEAD_LOCKED",
        "sealed_scope": {
            "scope_class": "CURRENT_HEAD_WORKTREE_SCOPE_ONLY",
            "scope_digest": "abc123",
        },
    }

    receipt = build_clean_current_head_receipt(
        root=tmp_path,
        required_refs=[tracked_rel, live_only_rel],
        current_head_truth_lock=lock,
    )

    assert receipt["status"] == "PASS"
    assert receipt["sealed_worktree_scope_accepted"] is True
    assert receipt["counted_authority_snapshot_mode"] == "SEALED_WORKTREE_SCOPE"


def test_authority_supersession_registry_mirrors_live_map() -> None:
    registry = build_authority_supersession_registry(root=repo_root())
    assert registry["status"] == "PASS"
    assert registry["report_mirror_ref"].endswith("authority_supersession_map.json")
    assert any(row["function_id"] == "blocker_matrix" for row in registry["rows"])
    assert GOVERNANCE_AUTHORITY_SUPERSESSION_REGISTRY_REL.endswith("authority_supersession_registry.json")
