from __future__ import annotations

import subprocess
from pathlib import Path

from tools.operator import kt_lane_preflight as preflight


def test_preflight_receipt_fails_dirty_worktree(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(preflight, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(preflight.common, "git_current_branch_name", lambda root: "main")
    monkeypatch.setattr(preflight.common, "git_rev_parse", lambda root, ref: "a" * 40)
    monkeypatch.setattr(preflight.common, "git_status_porcelain", lambda root: " M some/file.json")
    monkeypatch.setattr(preflight, "_is_ancestor", lambda root, ancestor, descendant: True)
    receipt = preflight.build_receipt(
        lane="TEST_LANE",
        expected_branch="main",
        source_outputs=[],
        overwrites=[],
        test_paths=[],
    )
    assert receipt["status"] == "FAIL"
    assert any(check["check"] == "worktree_clean" and check["status"] == "FAIL" for check in receipt["checks"])


def test_preflight_recommends_sharding_known_long_suite(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(preflight, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(preflight.common, "git_current_branch_name", lambda root: "feature")
    monkeypatch.setattr(preflight.common, "git_rev_parse", lambda root, ref: "a" * 40 if ref == "HEAD" else "b" * 40)
    monkeypatch.setattr(preflight.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(preflight, "_is_ancestor", lambda root, ancestor, descendant: True)
    receipt = preflight.build_receipt(
        lane="TEST_LANE",
        expected_branch="",
        source_outputs=[],
        overwrites=[],
        test_paths=["KT_PROD_CLEANROOM/tests/operator"],
    )
    test_plan = next(check for check in receipt["checks"] if check["check"] == "timeout_safe_test_plan")
    assert receipt["status"] == "PASS"
    assert test_plan["known_long_paths"] == ["KT_PROD_CLEANROOM/tests/operator"]


def test_preflight_missing_origin_main_returns_fail_receipt(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(preflight, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(preflight.common, "git_current_branch_name", lambda root: "feature")

    def fake_rev_parse(root: Path, ref: str) -> str:
        if ref == "origin/main":
            raise subprocess.CalledProcessError(128, ["git", "rev-parse", ref])
        return "a" * 40

    monkeypatch.setattr(preflight.common, "git_rev_parse", fake_rev_parse)
    monkeypatch.setattr(preflight.common, "git_status_porcelain", lambda root: "")
    receipt = preflight.build_receipt(
        lane="TEST_LANE",
        expected_branch="feature",
        source_outputs=[],
        overwrites=[],
        test_paths=[],
    )
    branch_context = next(check for check in receipt["checks"] if check["check"] == "branch_context")
    assert receipt["status"] == "FAIL"
    assert branch_context["status"] == "FAIL"
    assert branch_context["origin_main"] == ""
    assert "origin/main" in branch_context["reason"]
