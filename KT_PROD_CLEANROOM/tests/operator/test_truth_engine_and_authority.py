from __future__ import annotations

import json
from pathlib import Path

from tools.operator.truth_authority import build_settled_truth_source_receipt
from tools.operator.truth_engine import build_truth_receipts


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


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
