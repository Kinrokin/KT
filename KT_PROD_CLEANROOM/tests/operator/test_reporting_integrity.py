from __future__ import annotations

import json
import subprocess
from pathlib import Path

from tools.operator.reporting_integrity import repair_reporting_integrity, verify_reporting_integrity


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_call(root: Path, *args: str) -> None:
    subprocess.check_call(["git", "-C", str(root), *args])


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def _init_repo_with_remote(tmp_path: Path) -> None:
    _git_call(tmp_path, "init", "-b", "main")
    _git_call(tmp_path, "config", "user.email", "test@example.com")
    _git_call(tmp_path, "config", "user.name", "Test User")

    (tmp_path / "README.md").write_text("x\n", encoding="utf-8", newline="\n")
    _git_call(tmp_path, "add", "README.md")
    _git_call(tmp_path, "commit", "-m", "init")

    remote = (tmp_path / "remote.git").resolve()
    subprocess.check_call(["git", "init", "--bare", str(remote)])
    _git_call(tmp_path, "remote", "add", "origin", str(remote))

    # Push main and create a published ledger branch.
    _git_call(tmp_path, "push", "-u", "origin", "main")
    _git_call(tmp_path, "push", "origin", "HEAD:refs/heads/kt_truth_ledger")
    _git_call(tmp_path, "fetch", "origin", "kt_truth_ledger")


def _seed_convergence_artifacts(tmp_path: Path, *, head: str) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    gov = tmp_path / "KT_PROD_CLEANROOM" / "governance"
    truth = tmp_path / "KT_PROD_CLEANROOM" / "exports" / "_truth" / "current"

    _write_json(
        reports / "live_validation_index.json",
        {
            "schema_id": "kt.operator.live_validation_index.v1",
            "branch_ref": "main",
            "worktree": {"head_sha": head, "git_dirty": False},
        },
    )
    _write_json(
        gov / "execution_board.json",
        {
            "schema_id": "kt.governance.execution_board.v3",
            "last_synced_head_sha": head,
            "authoritative_current_head_truth_source": "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
            "authority_mode": "SETTLED_AUTHORITATIVE",
            "current_posture_state": "TRUTHFUL_GREEN",
            "program_gates": {"H1_ACTIVATION_ALLOWED": False},
        },
    )
    _write_json(
        gov / "readiness_scope_manifest.json",
        {
            "schema_id": "kt.governance.readiness_scope_manifest.v2",
            "authoritative_truth_source": "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
        },
    )
    _write_json(
        truth / "current_pointer.json",
        {
            "schema_id": "kt.operator.truth_pointer.v1",
            "truth_subject_commit": head,
            "posture_enum": "TRUTHFUL_GREEN",
        },
    )
    for name in ("current_state_receipt.json", "runtime_closure_audit.json"):
        _write_json(
            reports / name,
            {
                "schema_id": f"test.{name}",
                "validated_head_sha": head,
                "branch_ref": "main",
                "posture_state": "TRUTHFUL_GREEN",
                "status": "ACTIVE",
            },
        )
    _write_json(
        reports / "settled_truth_source_receipt.json",
        {
            "schema_id": "kt.operator.settled_truth_source_receipt.v1",
            "status": "SETTLED_AUTHORITATIVE",
            "pinned_head_sha": head,
            "derived_posture_state": "TRUTHFUL_GREEN",
        },
    )
    _write_json(
        reports / "one_button_preflight_receipt.json",
        {
            "schema_id": "kt.one_button_preflight_receipt.v2",
            "status": "PASS",
            "validated_head_sha": head,
            "head_lineage_match": True,
        },
    )
    _write_json(
        reports / "one_button_production_receipt.json",
        {
            "schema_id": "kt.one_button_production_receipt.v2",
            "status": "PASS",
            "validated_head_sha": head,
            "production_run": {"head_lineage_match": True, "nested_verdict_head_sha": head},
        },
    )


def test_verify_fails_closed_on_stale_or_contradictory_publication_reporting(tmp_path: Path) -> None:
    _init_repo_with_remote(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    _seed_convergence_artifacts(tmp_path, head=head)

    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    # Stale + contradictory: remote branch exists but receipts claim not published and old head.
    _write_json(
        reports / "authority_convergence_receipt.json",
        {
            "schema_id": "kt.operator.authority_convergence_receipt.v1",
            "generated_utc": "2026-01-01T00:00:00Z",
            "status": "PASS",
            "proof_class": "LOCAL_LEDGER_SELF_CONVERGENCE_ONLY",
            "observed": {"git_head": "old1111", "ledger_branch_published": False},
        },
    )
    _write_json(
        reports / "published_head_self_convergence_receipt.json",
        {
            "schema_id": "kt.operator.published_head_self_convergence_receipt.v1",
            "generated_utc": "2026-01-01T00:00:00Z",
            "status": "LOCAL_LEDGER_SELF_CONVERGENCE_ONLY",
            "proof_class": "LOCAL_LEDGER_SELF_CONVERGENCE_ONLY",
            "validated_head_sha": "old1111",
            "ledger_branch": "kt_truth_ledger",
            "ledger_branch_published": False,
            "ledger_branch_head_sha": "",
            "published_head_authority_claimed": False,
            "blockers": ["LEDGER_BRANCH_LOCAL_ONLY", "PUBLISHED_HEAD_SELF_CONVERGENCE_UNRESOLVED"],
            "main_live_truth_purged": True,
        },
    )

    receipt = verify_reporting_integrity(root=tmp_path)
    assert receipt["status"] == "FAIL_CLOSED", receipt
    assert receipt["contradictions"], receipt
    assert receipt["stale_findings"], receipt


def test_repair_recomputes_ledger_branch_published_and_clears_staleness(tmp_path: Path) -> None:
    _init_repo_with_remote(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    _seed_convergence_artifacts(tmp_path, head=head)

    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _write_json(
        reports / "authority_convergence_receipt.json",
        {
            "schema_id": "kt.operator.authority_convergence_receipt.v1",
            "generated_utc": "2026-01-01T00:00:00Z",
            "status": "PASS",
            "proof_class": "LOCAL_LEDGER_SELF_CONVERGENCE_ONLY",
            "observed": {"git_head": "old1111", "ledger_branch_published": False},
        },
    )
    _write_json(
        reports / "published_head_self_convergence_receipt.json",
        {
            "schema_id": "kt.operator.published_head_self_convergence_receipt.v1",
            "generated_utc": "2026-01-01T00:00:00Z",
            "status": "LOCAL_LEDGER_SELF_CONVERGENCE_ONLY",
            "proof_class": "LOCAL_LEDGER_SELF_CONVERGENCE_ONLY",
            "validated_head_sha": "old1111",
            "ledger_branch": "kt_truth_ledger",
            "ledger_branch_published": False,
            "ledger_branch_head_sha": "",
            "published_head_authority_claimed": False,
            "blockers": ["LEDGER_BRANCH_LOCAL_ONLY", "PUBLISHED_HEAD_SELF_CONVERGENCE_UNRESOLVED"],
            "main_live_truth_purged": True,
        },
    )

    repair = repair_reporting_integrity(root=tmp_path)
    assert repair["status"] == "PASS", repair
    assert repair["verification_after"]["status"] == "PASS", repair

    auth = json.loads((reports / "authority_convergence_receipt.json").read_text(encoding="utf-8"))
    assert auth["observed"]["git_head"] == head
    assert auth["observed"]["ledger_branch_published"] is True

    ph = json.loads((reports / "published_head_self_convergence_receipt.json").read_text(encoding="utf-8"))
    assert ph["validated_head_sha"] == head
    assert ph["ledger_branch_published"] is True
    assert ph["ledger_branch_head_sha"]

