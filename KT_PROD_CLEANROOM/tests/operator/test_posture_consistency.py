from __future__ import annotations

import json
from pathlib import Path

from tools.operator.posture_consistency import verify_posture


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _release_decision(posture_state: str) -> str:
    return {
        "TRUTH_DEFECTS_PRESENT": "NO_GO_TRUTH_DEFECTS_PRESENT",
        "CANONICAL_VALIDATED_DIRTY_WORKTREE": "HOLD_DIRTY_WORKTREE",
        "CANONICAL_READY_FOR_REEARNED_GREEN": "HOLD_CANONICAL_READY_FOR_REEARNED_GREEN",
        "TRUTHFUL_GREEN": "GO_PRESS_BUTTON_PRODUCTION_ELIGIBLE",
    }[posture_state]


def _seed_repo(tmp_path: Path, *, posture_state: str = "CANONICAL_READY_FOR_REEARNED_GREEN", equal_alias: bool = True) -> Path:
    worktree_dirty = posture_state == "CANONICAL_VALIDATED_DIRTY_WORKTREE"
    stop_gates = [] if posture_state == "TRUTHFUL_GREEN" else ["gate.truth"]
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "current_state_receipt.json",
        {
            "schema_id": "kt.operator.current_state_receipt.v3",
            "posture_state": posture_state,
            "branch_ref": "ops/test",
            "validated_head_sha": "abc123",
            "active_stop_gates": stop_gates,
            "current_release_decision": _release_decision(posture_state),
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "runtime_closure_audit.json",
        {
            "schema_id": "kt.operator.runtime_closure_audit.v3",
            "posture_state": posture_state,
            "branch_ref": "ops/test",
            "validated_head_sha": "abc123",
            "blocking_groups": stop_gates,
            "release_decision": _release_decision(posture_state),
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "live_validation_index.json",
        {
            "schema_id": "kt.operator.live_validation_index.v1",
            "branch_ref": "ops/test",
            "worktree": {
                "git_dirty": worktree_dirty,
                "head_sha": "abc123",
                "dirty_files": ["marker.txt"] if worktree_dirty else [],
            },
            "checks": [
                {
                    "check_id": "constitutional_guard",
                    "critical": True,
                    "dirty_sensitive": False,
                    "status": "PASS",
                },
                {
                    "check_id": "current_worktree_cleanroom_suite",
                    "critical": True,
                    "dirty_sensitive": True,
                    "status": "FAIL" if worktree_dirty else "PASS",
                },
            ],
        },
    )
    _write_json(tmp_path / "KT_PROD_CLEANROOM" / "reports" / "real_path_attachment_matrix.json", {
        "schema_id": "kt.operator.real_path_attachment_matrix.v1",
        "rows": [
            {"program_id": "program.certify.canonical_hmac", "safe_run_enforced": False, "attachment_status": "PASS"},
            {"program_id": "program.hat_demo", "safe_run_enforced": False, "attachment_status": "PASS"},
            {"program_id": "program.red_assault.serious_v1", "safe_run_enforced": False, "attachment_status": "PASS"},
            {"program_id": "program.hat_demo", "safe_run_enforced": True, "attachment_status": "PASS"},
        ],
    })
    _write_json(tmp_path / "KT_PROD_CLEANROOM" / "reports" / "source_integrity_receipt.json", {"status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM" / "reports" / "hashpin_receipt.json", {"target_count": 7})
    _write_json(tmp_path / "KT_PROD_CLEANROOM" / "reports" / "governance_manifest_verification.json", {"status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM" / "reports" / "program_catalog_report.json", {"status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM" / "reports" / "practice_mode_chain_summary.json", {"status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM" / "reports" / "twocleanclone_proof.json", {"status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM" / "reports" / "godstatus_verdict.json", {"status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM" / "reports" / "ci_gate_promotion_receipt.json", {"status": "WARN_ONLY_LIVE"})
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "one_button_preflight_receipt.json",
        {"status": "PASS", "validated_head_sha": "abc123", "branch_ref": "ops/test"},
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "one_button_production_receipt.json",
        {"status": "PASS", "validated_head_sha": "abc123", "branch_ref": "ops/test"},
    )
    _write_json(tmp_path / "KT_PROD_CLEANROOM" / "reports" / "main_branch_protection_receipt.json", {"status": "PASS"})

    authority_sha = "a" * 64
    titanium_sha = authority_sha if equal_alias else "b" * 64
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "governance_manifest.json",
        {
            "authority_os_sha256": authority_sha,
            "titanium_work_order_sha256": titanium_sha,
        },
    )
    alias_payload = {
        "authority_os_document_id": "AUTHORITY_OS",
        "titanium_work_order_document_id": "TITANIUM_WORK_ORDER",
        "authority_os_sha256": authority_sha,
        "titanium_work_order_sha256": titanium_sha,
        "authority_os_equals_titanium_work_order": equal_alias,
    }
    if equal_alias:
        alias_payload.update({"alias_type": "RATIFIED_ALIAS", "alias_rationale": "same canonical source"})
    else:
        alias_payload.update({"split_rationale": "distinct documents"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM" / "governance" / "governance_aliases.json", alias_payload)
    return tmp_path


def test_verify_posture_passes_for_ratified_alias(tmp_path: Path) -> None:
    root = _seed_repo(tmp_path, equal_alias=True)
    report = verify_posture(root=root, expected_posture="CANONICAL_READY_FOR_REEARNED_GREEN")
    assert report["status"] == "PASS"
    assert report["alias_truth"]["authority_os_equals_titanium_work_order"] is True


def test_verify_posture_accepts_ci_platform_block_status(tmp_path: Path) -> None:
    root = _seed_repo(tmp_path, equal_alias=True)
    _write_json(root / "KT_PROD_CLEANROOM" / "reports" / "ci_gate_promotion_receipt.json", {"status": "PASS_WITH_PLATFORM_BLOCK"})
    report = verify_posture(root=root, expected_posture="CANONICAL_READY_FOR_REEARNED_GREEN")
    assert report["status"] == "PASS"


def test_verify_posture_fails_on_posture_mismatch(tmp_path: Path) -> None:
    root = _seed_repo(tmp_path, posture_state="CANONICAL_VALIDATED_DIRTY_WORKTREE", equal_alias=True)
    try:
        verify_posture(root=root, expected_posture="CANONICAL_READY_FOR_REEARNED_GREEN")
    except RuntimeError as exc:
        assert "current_state_receipt posture_state" in str(exc)
    else:
        raise AssertionError("expected posture mismatch to fail closed")


def test_verify_posture_passes_for_truthful_green(tmp_path: Path) -> None:
    root = _seed_repo(tmp_path, posture_state="TRUTHFUL_GREEN", equal_alias=True)
    report = verify_posture(root=root, expected_posture="TRUTHFUL_GREEN")
    assert report["status"] == "PASS"
    assert report["one_button_state"]["status"] == "PASS"


def test_verify_posture_fails_when_required_real_path_row_is_not_pass(tmp_path: Path) -> None:
    root = _seed_repo(tmp_path, equal_alias=True)
    matrix_path = root / "KT_PROD_CLEANROOM" / "reports" / "real_path_attachment_matrix.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    matrix["rows"][0]["attachment_status"] = "FAIL_CLOSED"
    matrix["rows"][0]["failure_reason"] = "FAIL_CLOSED: repo is not clean"
    _write_json(matrix_path, matrix)

    try:
        verify_posture(root=root, expected_posture="CANONICAL_READY_FOR_REEARNED_GREEN")
    except RuntimeError as exc:
        assert "missing PASS attachment rows" in str(exc)
    else:
        raise AssertionError("expected real_path_attachment_matrix FAIL_CLOSED required row to fail closed")
