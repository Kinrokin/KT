from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from tools.operator.truth_publication import publish_truth_ledger_witness


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_publish_truth_ledger_witness_writes_required_ledger_current_receipts(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    head = "abc1234"
    _write_json(
        reports / "live_validation_index.json",
        {
            "schema_id": "kt.operator.live_validation_index.v1",
            "branch_ref": "main",
            "worktree": {"head_sha": head, "git_dirty": False},
            "checks": [],
        },
    )
    _write_json(
        reports / "current_state_receipt.json",
        {
            "schema_id": "kt.operator.current_state_receipt.v4",
            "validated_head_sha": head,
            "branch_ref": "main",
            "posture_state": "TRUTHFUL_GREEN",
            "status": "TRANSITIONAL",
        },
    )
    _write_json(
        reports / "runtime_closure_audit.json",
        {
            "schema_id": "kt.operator.runtime_closure_audit.v4",
            "validated_head_sha": head,
            "branch_ref": "main",
            "posture_state": "TRUTHFUL_GREEN",
            "status": "TRANSITIONAL",
        },
    )
    _write_json(reports / "posture_consistency_receipt.json", {"schema_id": "kt.operator.posture_consistency_receipt.v1", "status": "SKIP"})
    _write_json(
        reports / "posture_consistency_enforcement_receipt.json",
        {
            "schema_id": "kt.operator.posture_consistency_enforcement_receipt.v1",
            "status": "SKIP",
            "derived_state": "TRUTHFUL_GREEN",
        },
    )
    _write_json(reports / "posture_conflict_receipt.json", {"schema_id": "kt.operator.posture_conflict_receipt.v1", "status": "SKIP"})
    _write_json(
        reports / "settled_truth_source_receipt.json",
        {
            "schema_id": "kt.operator.settled_truth_source_receipt.v1",
            "status": "TRANSITIONAL_AUTHORITATIVE",
            "pinned_head_sha": head,
            "derived_posture_state": "TRUTHFUL_GREEN",
        },
    )
    _write_json(reports / "truth_supersession_receipt.json", {"schema_id": "kt.operator.truth_supersession_receipt.v1", "status": "PASS"})

    ledger_root = tmp_path / "ledger_root"
    publish_truth_ledger_witness(
        source_root=tmp_path,
        ledger_root=ledger_root,
        report_root_rel="reports",
        live_validation_index_path=reports / "live_validation_index.json",
        authority_mode="TRANSITIONAL_AUTHORITATIVE",
        posture_state="TRUTHFUL_GREEN",
    )

    current_dir = ledger_root / "ledger" / "current"
    assert current_dir.is_dir()
    current_state = json.loads((current_dir / "current_state_receipt.json").read_text(encoding="utf-8-sig"))
    runtime_audit = json.loads((current_dir / "runtime_closure_audit.json").read_text(encoding="utf-8-sig"))
    assert current_state["validated_head_sha"] == head
    assert runtime_audit["validated_head_sha"] == head

