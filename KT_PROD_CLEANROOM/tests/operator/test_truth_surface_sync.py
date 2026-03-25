from __future__ import annotations

import json
from pathlib import Path

from tools.operator.dependency_inventory_emit import build_dependency_reports
from tools.operator.truth_surface_sync import _sync_secondary_surfaces, build_receipts


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_dependency_reports(root: Path) -> None:
    reports = build_dependency_reports(root=root, scan_roots=("KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src",))
    _write_json(root / "KT_PROD_CLEANROOM" / "reports" / "dependency_inventory.json", reports["inventory"])
    _write_json(root / "KT_PROD_CLEANROOM" / "reports" / "python_environment_manifest.json", reports["environment"])
    _write_json(root / "KT_PROD_CLEANROOM" / "reports" / "sbom_cyclonedx.json", reports["sbom"])


def _write_platform_governance_receipts(root: Path, subject_head: str) -> None:
    _write_json(
        root / "KT_PROD_CLEANROOM" / "reports" / "main_branch_protection_receipt.json",
        {
            "schema_id": "kt.main_branch_protection_receipt.v2",
            "status": "BLOCKED",
            "claim_admissible": False,
            "platform_block": {"http_status": 403, "message": "blocked"},
            "validated_head_sha": subject_head,
        },
    )
    _write_json(
        root / "KT_PROD_CLEANROOM" / "reports" / "ci_gate_promotion_receipt.json",
        {
            "schema_id": "kt.sovereign.ci_gate_promotion_receipt.v1",
            "status": "PASS_WITH_PLATFORM_BLOCK",
            "head_sha": subject_head,
        },
    )


def test_sync_secondary_surfaces_updates_authority_mode_and_freeze_refs(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "readiness_scope_manifest.json",
        {
            "schema_id": "kt.governance.readiness_scope_manifest.v2",
            "readiness_includes_zones": ["CANONICAL"],
            "readiness_excludes_zones": ["LAB", "ARCHIVE", "COMMERCIAL", "GENERATED_RUNTIME_TRUTH", "QUARANTINED"],
            "current_blockers": [],
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "execution_board.json",
        {
            "schema_id": "kt.governance.execution_board.v2",
            "workstreams": [
                {"workstream_id": "PHASE_0_CORE_TRUTH_REPAIR", "status": "BLOCKED"},
                {"workstream_id": "PHASE_1_H0_FREEZE", "status": "BLOCKED"},
                {"workstream_id": "PHASE_2_TRUTH_ENGINE", "status": "BLOCKED"},
                {"workstream_id": "PHASE_3_BOUNDARY_PURIFICATION", "status": "BLOCKED"},
                {"workstream_id": "PHASE_4_SETTLED_AUTHORITY", "status": "BLOCKED"},
            ],
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "h0_freeze_policy.json",
        {
            "schema_id": "kt.governance.h0_freeze_policy.v2",
            "activation_state": "PENDING_TRUTHFUL_GREEN",
            "current_posture_state": "TRUTH_DEFECTS_PRESENT",
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "documentary_truth_policy.json",
        {
            "schema_id": "kt.governance.documentary_truth_policy.v1",
            "active_current_head_truth_source": "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
            "active_supporting_truth_surfaces": ["KT_PROD_CLEANROOM/reports/current_state_receipt.json"],
            "documentary_only_patterns": ["docs/**"],
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "exports" / "_truth" / "current" / "current_pointer.json",
        {"status": "ACTIVE"},
    )
    _write_dependency_reports(tmp_path)
    _write_platform_governance_receipts(tmp_path, "abc123")

    _sync_secondary_surfaces(
        root=tmp_path,
        posture_state="CANONICAL_READY_FOR_REEARNED_GREEN",
        live_head="abc123",
        truth_source_ref="KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
        authority_mode="SETTLED_AUTHORITATIVE",
        open_blockers=["CLEAN_CLONE_NOT_RUN"],
        convergence_status="FAIL",
        convergence_failures=["execution_board_matches_git_head"],
    )

    readiness = json.loads((tmp_path / "KT_PROD_CLEANROOM" / "governance" / "readiness_scope_manifest.json").read_text(encoding="utf-8"))
    board = json.loads((tmp_path / "KT_PROD_CLEANROOM" / "governance" / "execution_board.json").read_text(encoding="utf-8"))
    freeze = json.loads((tmp_path / "KT_PROD_CLEANROOM" / "governance" / "h0_freeze_policy.json").read_text(encoding="utf-8"))
    promotion = json.loads((tmp_path / "KT_PROD_CLEANROOM" / "reports" / "settled_authority_promotion_receipt.json").read_text(encoding="utf-8"))
    documentary = json.loads((tmp_path / "KT_PROD_CLEANROOM" / "reports" / "documentary_truth_validation_receipt.json").read_text(encoding="utf-8"))
    dependency = json.loads((tmp_path / "KT_PROD_CLEANROOM" / "reports" / "dependency_inventory_validation_receipt.json").read_text(encoding="utf-8"))
    narrowing = json.loads((tmp_path / "KT_PROD_CLEANROOM" / "reports" / "platform_governance_narrowing_receipt.json").read_text(encoding="utf-8"))
    verifier = json.loads((tmp_path / "KT_PROD_CLEANROOM" / "reports" / "public_verifier_manifest.json").read_text(encoding="utf-8"))

    assert readiness["current_authority_mode"] == "SETTLED_AUTHORITATIVE"
    assert readiness["authoritative_truth_source"] == "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json"
    assert "CLEAN_CLONE_NOT_RUN" in readiness["current_blockers"]

    assert board["authority_mode"] == "SETTLED_AUTHORITATIVE"
    assert board["schema_id"] == "kt.governance.execution_board.v3"
    assert board["status_taxonomy_ref"] == "KT_PROD_CLEANROOM/governance/status_taxonomy.json"
    assert board["completion_program_ref"] == "KT_PROD_CLEANROOM/docs/operator/KT_CONSTITUTIONAL_COMPLETION_PROGRAM.md"
    assert board["authoritative_current_head_truth_source"] == "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json"
    assert board["last_synced_head_sha"] == "abc123"
    assert board["program_gates"]["FOUNDATIONAL_LAW_TRANCHE_COMPLETE"] is True
    assert board["program_gates"]["TRUTH_PUBLICATION_STABILIZED"] is False
    assert board["program_gates"]["H1_ACTIVATION_ALLOWED"] is False
    assert board["current_constitutional_domain"]["domain_id"] == "DOMAIN_1_TRUTH_PUBLICATION_ARCHITECTURE"
    domain1 = next(row for row in board["constitutional_domains"] if row["domain_id"] == "DOMAIN_1_TRUTH_PUBLICATION_ARCHITECTURE")
    domain2 = next(row for row in board["constitutional_domains"] if row["domain_id"] == "DOMAIN_2_PROMOTION_CIVILIZATION")
    assert domain1["status"] == "SPECIFIED"
    assert domain1["maturity_state"] == "SPECIFIED"
    assert domain1["gate_state"] == "IN_PROGRESS"
    assert "CLEAN_CLONE_NOT_RUN" in domain1["active_blockers"]
    assert "authority convergence failed: execution_board_matches_git_head" in domain1["active_blockers"]
    assert domain2["status"] == "SPECIFIED"
    assert domain2["gate_state"] == "LOCKED"
    h1_gate = next(row for row in board["domain_gate_statuses"] if row["gate_id"] == "H1_ACTIVATION_ALLOWED")
    assert h1_gate["domain_id"] == "DOMAIN_2_PROMOTION_CIVILIZATION"
    assert h1_gate["open"] is False
    phase4 = next(row for row in board["workstreams"] if row["workstream_id"] == "PHASE_4_SETTLED_AUTHORITY")
    assert phase4["status"] == "COMPLETED"

    assert freeze["freeze_scope_manifest"] == "KT_PROD_CLEANROOM/governance/canonical_freeze_manifest.json"
    assert freeze["amendment_scope_manifest"] == "KT_PROD_CLEANROOM/governance/amendment_scope_manifest.json"
    assert promotion["new_authority_state"] == "SETTLED_AUTHORITATIVE"
    assert promotion["promotion_verdict"] == "PASS"
    assert documentary["status"] == "PASS"
    assert dependency["status"] == "PASS"
    assert narrowing["platform_governance_verdict"] == "WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED"
    assert narrowing["platform_governance_claim_admissible"] is False
    assert narrowing["platform_governance_subject_commit"] == "abc123"
    assert verifier["schema_id"] == "kt.public_verifier_manifest.v4"
    assert verifier["validated_head_sha"] == "abc123"
    assert verifier["evidence_commit"] == ""
    assert verifier["truth_subject_commit"] == "abc123"
    assert verifier["subject_verdict"] == "TRANSPARENCY_VERIFICATION_NOT_PROVEN"
    assert verifier["publication_receipt_status"] == "MISSING"
    assert verifier["evidence_contains_subject"] is False
    assert verifier["evidence_equals_subject"] is False
    assert verifier["platform_governance_verdict"] == "WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED"
    assert verifier["platform_governance_subject_commit"] == "abc123"
    assert verifier["platform_governance_claim_admissible"] is False
    assert verifier["workflow_governance_status"] == "PASS_WITH_PLATFORM_BLOCK"
    assert verifier["branch_protection_status"] == "BLOCKED"
    assert verifier["enterprise_legitimacy_ceiling"] == "WORKFLOW_GOVERNANCE_ONLY"
    assert verifier["truth_pointer_ref"] == "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json"
    assert "KT_PROD_CLEANROOM/reports/dependency_inventory_validation_receipt.json" in verifier["state_receipts"]
    assert "KT_PROD_CLEANROOM/reports/ci_gate_promotion_receipt.json" in verifier["state_receipts"]
    assert "KT_PROD_CLEANROOM/reports/platform_governance_narrowing_receipt.json" in verifier["state_receipts"]


def test_sync_secondary_surfaces_is_stable_on_repeat_sync(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "readiness_scope_manifest.json",
        {
            "schema_id": "kt.governance.readiness_scope_manifest.v2",
            "readiness_includes_zones": ["CANONICAL"],
            "readiness_excludes_zones": ["LAB", "ARCHIVE", "COMMERCIAL", "GENERATED_RUNTIME_TRUTH", "QUARANTINED"],
            "current_blockers": [],
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "execution_board.json",
        {
            "schema_id": "kt.governance.execution_board.v2",
            "workstreams": [
                {"workstream_id": "PHASE_0_CORE_TRUTH_REPAIR", "status": "BLOCKED"},
                {"workstream_id": "PHASE_1_H0_FREEZE", "status": "BLOCKED"},
                {"workstream_id": "PHASE_2_TRUTH_ENGINE", "status": "BLOCKED"},
                {"workstream_id": "PHASE_3_BOUNDARY_PURIFICATION", "status": "BLOCKED"},
                {"workstream_id": "PHASE_4_SETTLED_AUTHORITY", "status": "BLOCKED"},
            ],
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "h0_freeze_policy.json",
        {
            "schema_id": "kt.governance.h0_freeze_policy.v2",
            "activation_state": "PENDING_TRUTHFUL_GREEN",
            "current_posture_state": "TRUTH_DEFECTS_PRESENT",
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "documentary_truth_policy.json",
        {
            "schema_id": "kt.governance.documentary_truth_policy.v1",
            "active_current_head_truth_source": "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
            "active_supporting_truth_surfaces": ["KT_PROD_CLEANROOM/reports/current_state_receipt.json"],
            "documentary_only_patterns": ["docs/**"],
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "exports" / "_truth" / "current" / "current_pointer.json",
        {"status": "ACTIVE"},
    )
    _write_dependency_reports(tmp_path)
    _write_platform_governance_receipts(tmp_path, "abc123")

    _sync_secondary_surfaces(
        root=tmp_path,
        posture_state="CANONICAL_READY_FOR_REEARNED_GREEN",
        live_head="abc123",
        truth_source_ref="KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
        authority_mode="SETTLED_AUTHORITATIVE",
        open_blockers=["GREEN_NOT_REEARNED"],
        convergence_status="FAIL",
        convergence_failures=["current_pointer_matches_git_head"],
    )
    first_promotion = (tmp_path / "KT_PROD_CLEANROOM" / "reports" / "settled_authority_promotion_receipt.json").read_text(encoding="utf-8")
    first_board = (tmp_path / "KT_PROD_CLEANROOM" / "governance" / "execution_board.json").read_text(encoding="utf-8")

    _sync_secondary_surfaces(
        root=tmp_path,
        posture_state="CANONICAL_READY_FOR_REEARNED_GREEN",
        live_head="abc123",
        truth_source_ref="KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
        authority_mode="SETTLED_AUTHORITATIVE",
        open_blockers=["GREEN_NOT_REEARNED"],
        convergence_status="FAIL",
        convergence_failures=["current_pointer_matches_git_head"],
    )
    second_promotion = (tmp_path / "KT_PROD_CLEANROOM" / "reports" / "settled_authority_promotion_receipt.json").read_text(encoding="utf-8")
    second_board = (tmp_path / "KT_PROD_CLEANROOM" / "governance" / "execution_board.json").read_text(encoding="utf-8")

    assert first_promotion == second_promotion
    assert first_board == second_board


def test_build_receipts_promotes_truthful_green_from_validated_subject_not_carrier_head(tmp_path: Path) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    gov = tmp_path / "KT_PROD_CLEANROOM" / "governance"
    _write_json(
        reports / "one_button_preflight_receipt.json",
        {
            "schema_id": "kt.one_button_preflight_receipt.v2",
            "status": "PASS",
            "validated_head_sha": "subject123",
            "publication_carrier_head_sha": "carrier456",
            "head_relation": "PUBLICATION_CARRIER_OF_VALIDATED_SUBJECT",
            "branch_ref": "ops/test",
        },
    )
    _write_json(
        reports / "one_button_production_receipt.json",
        {
            "schema_id": "kt.one_button_production_receipt.v2",
            "status": "PASS",
            "validated_head_sha": "subject123",
            "publication_carrier_head_sha": "carrier456",
            "head_relation": "PUBLICATION_CARRIER_OF_VALIDATED_SUBJECT",
            "branch_ref": "ops/test",
        },
    )
    _write_json(reports / "main_branch_protection_receipt.json", {"schema_id": "kt.main_branch_protection_receipt.v2", "status": "BLOCKED"})
    _write_json(gov / "documentary_truth_policy.json", {"schema_id": "kt.governance.documentary_truth_policy.v1", "active_current_head_truth_source": "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json"})

    index = {
        "generated_utc": "2026-03-25T20:00:00Z",
        "branch_ref": "ops/test",
        "worktree": {
            "git_dirty": False,
            "head_sha": "carrier456",
            "validated_subject_head_sha": "subject123",
            "publication_carrier_head_sha": "carrier456",
            "head_relation": "PUBLICATION_CARRIER_OF_VALIDATED_SUBJECT",
        },
        "checks": [
            {"check_id": "constitutional_guard", "critical": True, "dirty_sensitive": False, "status": "PASS"},
            {"check_id": "operator_clean_clone_smoke", "critical": True, "dirty_sensitive": False, "status": "PASS"},
        ],
    }

    receipts = build_receipts(
        root=tmp_path,
        index=index,
        report_root_rel="KT_PROD_CLEANROOM/reports",
        live_validation_index_ref="KT_PROD_CLEANROOM/reports/live_validation_index.json",
    )

    assert receipts["current_state"]["posture_state"] == "TRUTHFUL_GREEN"
    assert receipts["current_state"]["validated_head_sha"] == "subject123"
    assert receipts["current_state"]["publication_carrier_head_sha"] == "carrier456"
