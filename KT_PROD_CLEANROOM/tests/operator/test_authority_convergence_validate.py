from __future__ import annotations

import json
from pathlib import Path

from tools.operator.authority_convergence_validate import build_authority_convergence_report


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _seed(tmp_path: Path, *, head: str, pointer_head: str, posture: str = "TRUTHFUL_GREEN") -> None:
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
            "current_posture_state": posture,
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
            "truth_subject_commit": pointer_head,
            "posture_enum": posture,
        },
    )
    for name in ("current_state_receipt.json", "runtime_closure_audit.json"):
        _write_json(
            reports / name,
            {
                "schema_id": f"test.{name}",
                "validated_head_sha": head,
                "branch_ref": "main",
                "posture_state": posture,
            },
        )
    _write_json(
        reports / "settled_truth_source_receipt.json",
        {
            "schema_id": "kt.operator.settled_truth_source_receipt.v1",
            "status": "SETTLED_AUTHORITATIVE",
            "pinned_head_sha": head,
            "derived_posture_state": posture,
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


def test_authority_convergence_passes_when_all_heads_and_posture_align(tmp_path: Path) -> None:
    _seed(tmp_path, head="abc1234", pointer_head="abc1234")
    report = build_authority_convergence_report(root=tmp_path)
    assert report["status"] == "PASS", report


def test_authority_convergence_fails_when_pointer_head_is_stale(tmp_path: Path) -> None:
    _seed(tmp_path, head="abc1234", pointer_head="def4567")
    report = build_authority_convergence_report(root=tmp_path)
    assert report["status"] == "FAIL"
    assert "current_pointer_matches_git_head" in report["failures"]
