from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator.truth_publication import (
    CURRENT_POINTER_REL,
    LEDGER_CURRENT_POINTER_REL,
    build_in_toto_statement_for_authority_subject,
    publish_truth_artifacts,
    publish_truth_ledger_witness,
    validate_truth_publication,
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _seed_law(root: Path) -> None:
    gov = root / "KT_PROD_CLEANROOM" / "governance"
    for name in (
        "truth_publication_contract.json",
        "settled_authority_migration_contract.json",
        "truth_snapshot_retention_rules.json",
        "truth_publication_cleanliness_rules.json",
        "tracked_vs_generated_truth_boundary.json",
        "truth_bundle_contract.json",
        "truth_pointer_rules.json",
        "current_pointer_transition_rules.json",
    ):
        _write_json(gov / name, {"schema_id": f"test.{name}", "status": "ACTIVE"})
    _write_json(
        gov / "execution_board.json",
        {
            "schema_id": "kt.governance.execution_board.v3",
            "authoritative_current_head_truth_source": CURRENT_POINTER_REL,
            "last_synced_head_sha": "abc123",
            "authority_mode": "SETTLED_AUTHORITATIVE",
            "current_posture_state": "TRUTHFUL_GREEN",
        },
    )
    _write_json(
        gov / "readiness_scope_manifest.json",
        {
            "schema_id": "kt.governance.readiness_scope_manifest.v2",
            "authoritative_truth_source": CURRENT_POINTER_REL,
        },
    )


def _seed_reports(root: Path) -> Path:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    live_validation_index = reports / "live_validation_index.json"
    _write_json(
        live_validation_index,
        {
            "schema_id": "kt.operator.live_validation_index.v1",
            "generated_utc": "2026-03-10T00:00:00Z",
            "branch_ref": "main",
            "worktree": {"git_dirty": False, "head_sha": "abc123", "dirty_files": []},
            "checks": [
                {"check_id": "constitutional_guard", "critical": True, "dirty_sensitive": False, "status": "PASS"},
                {"check_id": "operator_clean_clone_smoke", "critical": True, "dirty_sensitive": False, "status": "PASS"},
            ],
        },
    )
    for name, payload in {
        "current_state_receipt.json": {
            "schema_id": "kt.operator.current_state_receipt.v3",
            "generated_utc": "2026-03-10T00:00:00Z",
            "posture_state": "TRUTHFUL_GREEN",
            "validated_head_sha": "abc123",
            "branch_ref": "main",
            "status": "PASS",
        },
        "runtime_closure_audit.json": {
            "schema_id": "kt.operator.runtime_closure_audit.v3",
            "generated_utc": "2026-03-10T00:00:00Z",
            "posture_state": "TRUTHFUL_GREEN",
            "validated_head_sha": "abc123",
            "branch_ref": "main",
            "status": "PASS",
        },
        "posture_consistency_receipt.json": {
            "schema_id": "kt.operator.posture_consistency_receipt.v1",
            "generated_utc": "2026-03-10T00:00:00Z",
            "posture_state": "TRUTHFUL_GREEN",
            "validated_head_sha": "abc123",
            "status": "PASS",
        },
        "posture_consistency_enforcement_receipt.json": {
            "schema_id": "kt.operator.posture_consistency_enforcement_receipt.v1",
            "generated_utc": "2026-03-10T00:00:00Z",
            "derived_state": "TRUTHFUL_GREEN",
            "status": "PASS",
        },
        "posture_conflict_receipt.json": {
            "schema_id": "kt.operator.posture_conflict_receipt.v1",
            "generated_utc": "2026-03-10T00:00:00Z",
            "derived_state": "TRUTHFUL_GREEN",
            "status": "PASS",
            "conflicts": [],
        },
        "settled_truth_source_receipt.json": {
            "schema_id": "kt.operator.settled_truth_source_receipt.v1",
            "generated_utc": "2026-03-10T00:00:00Z",
            "status": "SETTLED_AUTHORITATIVE",
            "pinned_head_sha": "abc123",
            "derived_posture_state": "TRUTHFUL_GREEN",
        },
        "truth_supersession_receipt.json": {
            "schema_id": "kt.operator.truth_supersession_receipt.v1",
            "generated_utc": "2026-03-10T00:00:00Z",
            "status": "PASS",
            "derived_posture_state": "TRUTHFUL_GREEN",
        },
        "settled_authority_promotion_receipt.json": {
            "schema_id": "kt.operator.settled_authority_promotion_receipt.v1",
            "generated_utc": "2026-03-10T00:00:00Z",
            "promotion_verdict": "PASS",
        },
        "one_button_preflight_receipt.json": {
            "schema_id": "kt.one_button_preflight_receipt.v2",
            "created_utc": "2026-03-10T00:00:00Z",
            "status": "PASS",
            "validated_head_sha": "abc123",
            "branch_ref": "main",
            "head_lineage_match": True,
        },
        "one_button_production_receipt.json": {
            "schema_id": "kt.one_button_production_receipt.v2",
            "created_utc": "2026-03-10T00:00:00Z",
            "status": "PASS",
            "validated_head_sha": "abc123",
            "branch_ref": "main",
            "production_run": {
                "head_lineage_match": True,
                "nested_verdict_head_sha": "abc123",
            },
        },
    }.items():
        _write_json(reports / name, payload)
    return live_validation_index


def test_publish_truth_artifacts_emits_bundle_pointer_and_indexes(tmp_path: Path) -> None:
    _seed_law(tmp_path)
    live_validation_index = _seed_reports(tmp_path)

    publication = publish_truth_artifacts(
        root=tmp_path,
        report_root_rel="KT_PROD_CLEANROOM/reports",
        live_validation_index_path=live_validation_index,
        authority_mode="SETTLED_AUTHORITATIVE",
        posture_state="TRUTHFUL_GREEN",
        board_open_blockers=[],
    )

    pointer = json.loads((tmp_path / CURRENT_POINTER_REL).read_text(encoding="utf-8"))
    assert pointer["current_bundle_hash"] == publication["truth_bundle_hash"]
    assert publication["current_pointer_ref"] == CURRENT_POINTER_REL
    assert (tmp_path / "KT_PROD_CLEANROOM" / "reports" / "truth_publication_receipt.json").exists()
    assert (tmp_path / "KT_PROD_CLEANROOM" / "reports" / "truth_publication_stabilization_receipt.json").exists()


def test_validate_truth_publication_passes_when_pointer_and_board_are_aligned(tmp_path: Path) -> None:
    _seed_law(tmp_path)
    live_validation_index = _seed_reports(tmp_path)
    publish_truth_artifacts(
        root=tmp_path,
        report_root_rel="KT_PROD_CLEANROOM/reports",
        live_validation_index_path=live_validation_index,
        authority_mode="SETTLED_AUTHORITATIVE",
        posture_state="TRUTHFUL_GREEN",
        board_open_blockers=[],
    )

    report = validate_truth_publication(root=tmp_path)
    assert report["status"] == "PASS", report


def test_publish_truth_artifacts_is_stable_on_repeat_publish(tmp_path: Path) -> None:
    _seed_law(tmp_path)
    live_validation_index = _seed_reports(tmp_path)

    first = publish_truth_artifacts(
        root=tmp_path,
        report_root_rel="KT_PROD_CLEANROOM/reports",
        live_validation_index_path=live_validation_index,
        authority_mode="SETTLED_AUTHORITATIVE",
        posture_state="TRUTHFUL_GREEN",
        board_open_blockers=[],
    )
    second = publish_truth_artifacts(
        root=tmp_path,
        report_root_rel="KT_PROD_CLEANROOM/reports",
        live_validation_index_path=live_validation_index,
        authority_mode="SETTLED_AUTHORITATIVE",
        posture_state="TRUTHFUL_GREEN",
        board_open_blockers=[],
    )

    assert first["truth_bundle_hash"] == second["truth_bundle_hash"]
    assert first["truth_bundle_ref"] == second["truth_bundle_ref"]
    pointer = json.loads((tmp_path / CURRENT_POINTER_REL).read_text(encoding="utf-8"))
    assert pointer["supersedes_bundle_hash"] == ""


def test_publish_truth_ledger_witness_emits_bootstrap_bundle_outside_main(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    ledger_root = tmp_path / "ledger"
    _seed_law(source_root)
    live_validation_index = _seed_reports(source_root)

    publication = publish_truth_ledger_witness(
        source_root=source_root,
        ledger_root=ledger_root,
        report_root_rel="KT_PROD_CLEANROOM/reports",
        live_validation_index_path=live_validation_index,
        authority_mode="TRANSITIONAL_AUTHORITATIVE",
        posture_state="CANONICAL_READY_FOR_REEARNED_GREEN",
        ledger_branch="kt_truth_ledger",
    )

    pointer = json.loads((ledger_root / LEDGER_CURRENT_POINTER_REL).read_text(encoding="utf-8"))
    assert publication["current_pointer_ref"] == "kt_truth_ledger:ledger/current/current_pointer.json"
    assert pointer["witness_plane"] is True
    assert pointer["published_head_authority_claimed"] is False
    assert not (source_root / LEDGER_CURRENT_POINTER_REL).exists()


def test_build_in_toto_statement_binds_subject_sha256() -> None:
    sha = "a" * 64
    stmt = build_in_toto_statement_for_authority_subject(subject_sha256_hex=sha, subject_name="test-subject")
    assert stmt["_type"] == "https://in-toto.io/Statement/v0.1"
    assert stmt["subject"][0]["digest"]["sha256"] == sha


def test_build_in_toto_statement_rejects_invalid_sha256() -> None:
    with pytest.raises(RuntimeError):
        build_in_toto_statement_for_authority_subject(subject_sha256_hex="nothex", subject_name="x")
