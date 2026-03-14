from __future__ import annotations

import json
import subprocess
from pathlib import Path

from tools.operator.platform_governance_narrowing import (
    PLATFORM_GOVERNANCE_VERDICT_PROVEN,
    PLATFORM_GOVERNANCE_VERDICT_WORKFLOW_ONLY,
    build_platform_governance_claims,
    build_platform_governance_narrowing_receipt,
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _git(tmp_path: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(tmp_path), *args], text=True).strip()


def _init_git_repo(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test User")
    (tmp_path / "README.md").write_text("base\n", encoding="utf-8")
    _git(tmp_path, "add", "README.md")
    _git(tmp_path, "commit", "-m", "base")


def test_build_platform_governance_claims_narrows_to_workflow_only_when_branch_protection_blocked(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "main_branch_protection_receipt.json",
        {
            "status": "BLOCKED",
            "claim_admissible": False,
            "platform_block": {"http_status": 403, "message": "blocked"},
            "validated_head_sha": "a" * 40,
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "ci_gate_promotion_receipt.json",
        {
            "status": "PASS_WITH_PLATFORM_BLOCK",
            "head_sha": "a" * 40,
        },
    )

    claims = build_platform_governance_claims(root=tmp_path)

    assert claims["platform_governance_verdict"] == PLATFORM_GOVERNANCE_VERDICT_WORKFLOW_ONLY
    assert claims["platform_governance_subject_commit"] == "a" * 40
    assert claims["platform_governance_claim_admissible"] is False
    assert claims["workflow_governance_status"] == "PASS_WITH_PLATFORM_BLOCK"
    assert claims["branch_protection_status"] == "BLOCKED"
    assert claims["enterprise_legitimacy_ceiling"] == "WORKFLOW_GOVERNANCE_ONLY"


def test_build_platform_governance_narrowing_receipt_marks_platform_enforcement_proven_when_branch_receipt_passes(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "main_branch_protection_receipt.json",
        {
            "status": "PASS",
            "claim_admissible": True,
            "validated_head_sha": "b" * 40,
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "ci_gate_promotion_receipt.json",
        {
            "status": "PASS",
            "head_sha": "b" * 40,
        },
    )

    receipt = build_platform_governance_narrowing_receipt(root=tmp_path)

    assert receipt["platform_governance_verdict"] == PLATFORM_GOVERNANCE_VERDICT_PROVEN
    assert receipt["platform_governance_subject_commit"] == "b" * 40
    assert receipt["platform_governance_claim_admissible"] is True
    assert receipt["workflow_governance_status"] == "PASS"
    assert receipt["branch_protection_status"] == "PASS"
    assert receipt["validated_head_sha"]
