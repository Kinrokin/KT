from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.platform_governance_finalize import (
    DECISION_MODE_NARROWED,
    DECISION_MODE_PROVEN,
    build_platform_governance_final_claims,
    emit_platform_governance_finalization,
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def _git(tmp_path: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(tmp_path), *args], text=True).strip()


def _init_git_repo(tmp_path: Path) -> str:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test User")
    (tmp_path / "README.md").write_text("base\n", encoding="utf-8", newline="\n")
    _git(tmp_path, "add", "README.md")
    _git(tmp_path, "commit", "-m", "base")
    return _git(tmp_path, "rev-parse", "HEAD")


def _seed_common_receipts(tmp_path: Path, *, branch_status: str, branch_claim_admissible: bool, ci_status: str) -> str:
    head = _init_git_repo(tmp_path)
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "main_branch_protection_receipt.json",
        {
            "schema_id": "kt.main_branch_protection_receipt.v2",
            "status": branch_status,
            "claim_admissible": branch_claim_admissible,
            "validated_head_sha": head,
            "platform_block": {"http_status": 403, "message": "blocked"} if branch_status != "PASS" else None,
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "ci_gate_promotion_receipt.json",
        {
            "schema_id": "kt.sovereign.ci_gate_promotion_receipt.v1",
            "status": ci_status,
            "head_sha": head,
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "platform_governance_narrowing_receipt.json",
        {
            "schema_id": "kt.operator.platform_governance_narrowing_receipt.v1",
            "platform_governance_subject_commit": head,
            "platform_governance_verdict": "WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED",
            "platform_governance_claim_admissible": False,
            "workflow_governance_status": ci_status,
            "branch_protection_status": branch_status,
            "platform_governance_claim_boundary": "workflow governance only",
            "enterprise_legitimacy_ceiling": "WORKFLOW_GOVERNANCE_ONLY",
            "platform_governance_receipt_refs": [
                "KT_PROD_CLEANROOM/reports/ci_gate_promotion_receipt.json",
                "KT_PROD_CLEANROOM/reports/main_branch_protection_receipt.json",
            ],
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "public_verifier_manifest.json",
        {
            "schema_id": "kt.public_verifier_manifest.v4",
            "status": "PASS",
            "validated_head_sha": head,
            "evidence_commit": "e" * 40,
            "truth_subject_commit": "t" * 40,
            "subject_verdict": "PUBLISHED_HEAD_TRANSPARENCY_VERIFIED",
            "publication_receipt_status": "PASS",
            "evidence_contains_subject": True,
            "evidence_equals_subject": False,
            "claim_boundary": "boundary",
            "state_receipts": ["KT_PROD_CLEANROOM/reports/platform_governance_narrowing_receipt.json"],
            "publication_evidence_refs": [],
        },
    )
    _write_json(tmp_path / "KT_PROD_CLEANROOM" / "reports" / "authority_convergence_receipt.json", {"status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM" / "reports" / "cryptographic_publication_receipt.json", {"status": "PASS"})
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", "seed governance receipts")
    return head


def test_emit_platform_governance_finalization_narrows_cleanly(tmp_path: Path) -> None:
    head = _seed_common_receipts(tmp_path, branch_status="BLOCKED", branch_claim_admissible=False, ci_status="PASS_WITH_PLATFORM_BLOCK")

    receipt = emit_platform_governance_finalization(root=tmp_path)

    assert receipt["status"] == "PASS"
    assert receipt["decision_mode"] == DECISION_MODE_NARROWED
    assert receipt["platform_governance_verdict"] == "WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED"
    assert receipt["platform_governance_subject_commit"] == head
    assert receipt["unexpected_touches"] == []
    assert receipt["protected_touch_violations"] == []

    manifest = json.loads((tmp_path / "KT_PROD_CLEANROOM" / "reports" / "public_verifier_manifest.json").read_text(encoding="utf-8"))
    assert "KT_PROD_CLEANROOM/reports/kt_platform_governance_final_decision_receipt.json" in manifest["state_receipts"]
    claims = build_platform_governance_final_claims(root=tmp_path)
    assert claims["platform_governance_verdict"] == "WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED"


def test_emit_platform_governance_finalization_marks_platform_proven_when_live_receipts_allow_it(tmp_path: Path) -> None:
    _seed_common_receipts(tmp_path, branch_status="PASS", branch_claim_admissible=True, ci_status="PASS")

    receipt = emit_platform_governance_finalization(root=tmp_path)

    assert receipt["status"] == "PASS"
    assert receipt["decision_mode"] == DECISION_MODE_PROVEN
    assert receipt["platform_governance_verdict"] == "PLATFORM_ENFORCEMENT_PROVEN"
    assert receipt["platform_governance_claim_admissible"] is True
