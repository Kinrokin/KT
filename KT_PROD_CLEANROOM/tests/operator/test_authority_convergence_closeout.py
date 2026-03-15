from __future__ import annotations

import json
import subprocess
from pathlib import Path

from tools.operator.authority_convergence_closeout import build_authority_closure_receipt, build_kt_published_head_self_convergence_receipt


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_call(root: Path, *args: str) -> None:
    subprocess.check_call(["git", "-C", str(root), *args])


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _init_repo(tmp_path: Path) -> None:
    _git_call(tmp_path, "init", "-b", "main")
    _git_call(tmp_path, "config", "user.email", "test@example.com")
    _git_call(tmp_path, "config", "user.name", "Test User")
    (tmp_path / "README.md").write_text("base\n", encoding="utf-8")
    _git_call(tmp_path, "add", "README.md")
    _git_call(tmp_path, "commit", "-m", "base")


def test_authority_closeout_wraps_legacy_pass_receipts_with_no_unexpected_touches(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"

    _write_json(
        reports / "authority_convergence_receipt.json",
        {
            "schema_id": "kt.operator.authority_convergence_receipt.v2",
            "status": "PASS",
            "proof_class": "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN",
            "published_head_authority_claimed": True,
            "current_head_authority_claimed": True,
            "h1_admissible": False,
            "failures": [],
            "observed": {
                "truth_subject_commit": head,
                "evidence_commit": head,
                "current_head_commit": head,
                "ledger_branch_published": True,
                "ledger_branch_head_sha": head,
                "ledger_pointer_head": head,
                "ledger_current_state_head": head,
                "ledger_runtime_audit_head": head,
            },
        },
    )
    _write_json(
        reports / "published_head_self_convergence_receipt.json",
        {
            "schema_id": "kt.operator.published_head_self_convergence_receipt.v2",
            "status": "PASS",
            "proof_class": "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN",
            "validated_head_sha": head,
            "truth_subject_commit": head,
            "evidence_commit": head,
            "current_head_commit": head,
            "head_equals_subject": True,
            "current_head_claim_verdict": "HEAD_IS_TRANSPARENCY_VERIFIED_SUBJECT",
            "published_head_authority_claimed": True,
            "current_head_authority_claimed": True,
            "ledger_branch_published": True,
            "ledger_branch_head_sha": head,
            "main_live_truth_purged": True,
            "blockers": [],
        },
    )
    _write_json(
        reports / "reporting_integrity_repair_receipt.json",
        {
            "schema_id": "kt.operator.reporting_integrity_repair_receipt.v2",
            "status": "PASS",
        },
    )

    kt_published = build_kt_published_head_self_convergence_receipt(root=tmp_path)
    _write_json(reports / "kt_published_head_self_convergence_receipt.json", kt_published)
    _git_call(tmp_path, "add", ".")
    _git_call(tmp_path, "commit", "-m", "seed ws9 receipts")
    closure = build_authority_closure_receipt(root=tmp_path, generated_utc="2026-03-15T00:00:00Z")

    assert kt_published["status"] == "PASS"
    assert kt_published["pass_verdict"] == "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN"
    assert closure["status"] == "PASS", closure
    assert closure["pass_verdict"] == "AUTHORITY_AND_PUBLISHED_HEAD_CLOSED"
    assert closure["unexpected_touches"] == []
    assert closure["protected_touch_violations"] == []
