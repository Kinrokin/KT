from __future__ import annotations

from pathlib import Path

from tools.operator import ci_governance_receipt


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_build_ci_gate_receipt_marks_platform_block_without_upgrading_governance(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(ci_governance_receipt, "repo_root", lambda: tmp_path)
    _write_text(tmp_path / ".github" / "workflows" / "ci_p0_fail_closed_main.yml", "name: fail\n")
    _write_text(tmp_path / ".github" / "workflows" / "ci_p0_warn_only_closure.yml", "name: warn\n")

    receipt = ci_governance_receipt._build_ci_gate_receipt(
        repo_slug="Kinrokin/KT",
        branch_ref="main",
        head_sha="a" * 40,
        fail_workflow={"name": "P0 Fail-Closed Main Ladder", "state": "active", "path": ".github/workflows/ci_p0_fail_closed_main.yml"},
        warn_workflow={"name": "P0 Warn-Only Closure Ladder", "state": "active", "path": ".github/workflows/ci_p0_warn_only_closure.yml"},
        fail_run={
            "id": 1,
            "name": "P0 Fail-Closed Main Ladder",
            "head_sha": "a" * 40,
            "status": "completed",
            "conclusion": "success",
            "event": "push",
            "html_url": "https://example.invalid/runs/1",
            "display_title": "test run",
        },
        warn_run=None,
        fail_jobs=[{"name": "ws1", "conclusion": "success", "html_url": "https://example.invalid/jobs/1"}],
        branch_receipt={
            "status": "BLOCKED",
            "claim_admissible": False,
            "platform_block": {"http_status": 403, "message": "blocked"},
            "next_action": "upgrade plan",
        },
        desired_ruleset_artifact="KT_PROD_CLEANROOM/governance/platform/github_main_ruleset.json",
        desired_ruleset_sha256="deadbeef",
        historical_active_status="PASS",
    )

    assert receipt["status"] == "PASS_WITH_PLATFORM_BLOCK"
    assert receipt["fail_closed_main_workflow"]["promotion_status"] == "CURRENT_HEAD_PASS"
    assert receipt["branch_protection_ruleset"]["current_head_admissible"] is False
    assert "Do not claim platform-enforced governance on main while ruleset verification remains blocked." in receipt["next_actions"]


def test_build_ci_gate_receipt_marks_current_head_admissible_when_branch_protection_passes(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(ci_governance_receipt, "repo_root", lambda: tmp_path)
    _write_text(tmp_path / ".github" / "workflows" / "ci_p0_fail_closed_main.yml", "name: fail\n")
    _write_text(tmp_path / ".github" / "workflows" / "ci_p0_warn_only_closure.yml", "name: warn\n")

    receipt = ci_governance_receipt._build_ci_gate_receipt(
        repo_slug="Kinrokin/KT",
        branch_ref="main",
        head_sha="b" * 40,
        fail_workflow={"name": "P0 Fail-Closed Main Ladder", "state": "active", "path": ".github/workflows/ci_p0_fail_closed_main.yml"},
        warn_workflow={"name": "P0 Warn-Only Closure Ladder", "state": "active", "path": ".github/workflows/ci_p0_warn_only_closure.yml"},
        fail_run={
            "id": 2,
            "name": "P0 Fail-Closed Main Ladder",
            "head_sha": "b" * 40,
            "status": "completed",
            "conclusion": "success",
            "event": "push",
            "html_url": "https://example.invalid/runs/2",
            "display_title": "test run",
        },
        warn_run=None,
        fail_jobs=[],
        branch_receipt={
            "status": "PASS",
            "claim_admissible": True,
            "next_action": "none",
        },
        desired_ruleset_artifact="KT_PROD_CLEANROOM/governance/platform/github_main_ruleset.json",
        desired_ruleset_sha256="feedface",
        historical_active_status="PASS",
    )

    assert receipt["status"] == "PASS"
    assert receipt["branch_protection_ruleset"]["current_head_admissible"] is True
