from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_trust_zone_registry_scope_contract_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_trust_zone_scope_contract_binds_required_law(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    governance = tmp_path / "KT_PROD_CLEANROOM" / "governance"
    _write_json(
        reports / "cohort0_trust_zone_boundary_purification_authority_receipt.json",
        {"schema_id": "authority", "status": "PASS", "outcome": "OK", "next_lawful_move": "AUTHOR_TRUST_ZONE_BOUNDARY_PURIFICATION_REGISTRY_AND_SCOPE_CONTRACT"},
    )
    _write_json(
        reports / "cohort0_post_merge_canonical_truth_boundary_readiness_audit_receipt.json",
        {
            "schema_id": "audit",
            "status": "PASS",
            "outcome": "OK",
            "next_lawful_move": "PROMOTE_TRUST_ZONE_BOUNDARY_PURIFICATION_AS_NEXT_AUTHORITATIVE_LANE",
            "package_promotion_remains_deferred": True,
        },
    )
    _write_json(governance / "trust_zone_registry.json", {"schema_id": "registry", "registry_id": "REG", "zones": [{"zone_id": "CANONICAL"}]})
    _write_json(governance / "canonical_scope_manifest.json", {"schema_id": "canonical", "manifest_id": "CANON"})
    _write_json(governance / "readiness_scope_manifest.json", {"schema_id": "readiness", "manifest_id": "READY"})

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_git_rev_parse", lambda root, ref: "abc123")
    monkeypatch.setattr(tranche, "validate_trust_zones", lambda root: {"schema_id": "validation", "status": "PASS", "checks": [], "failures": []})

    result = tranche.run(
        reports_root=reports,
        governance_root=governance,
        authority_receipt_path=reports / "cohort0_trust_zone_boundary_purification_authority_receipt.json",
        post_merge_audit_receipt_path=reports / "cohort0_post_merge_canonical_truth_boundary_readiness_audit_receipt.json",
        trust_zone_registry_path=governance / "trust_zone_registry.json",
        canonical_scope_manifest_path=governance / "canonical_scope_manifest.json",
        readiness_scope_manifest_path=governance / "readiness_scope_manifest.json",
    )

    assert result["outcome"] == tranche.OUTCOME
    contract = _load(governance / tranche.GOVERNANCE_CONTRACT)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE
    assert contract["scope_rules"]["can_drive_live_posture"] == ["CANONICAL"]
    assert "deferred_package_artifact_misuse" in [row["class_id"] for row in contract["violation_classes"]]
    assert contract["failure_law"]["blocking"]


def test_trust_zone_scope_contract_requires_deferred_package_boundary(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    governance = tmp_path / "KT_PROD_CLEANROOM" / "governance"
    _write_json(
        reports / "cohort0_trust_zone_boundary_purification_authority_receipt.json",
        {"schema_id": "authority", "status": "PASS", "next_lawful_move": "AUTHOR_TRUST_ZONE_BOUNDARY_PURIFICATION_REGISTRY_AND_SCOPE_CONTRACT"},
    )
    _write_json(
        reports / "cohort0_post_merge_canonical_truth_boundary_readiness_audit_receipt.json",
        {"schema_id": "audit", "status": "PASS", "next_lawful_move": "PROMOTE_TRUST_ZONE_BOUNDARY_PURIFICATION_AS_NEXT_AUTHORITATIVE_LANE", "package_promotion_remains_deferred": False},
    )
    _write_json(governance / "trust_zone_registry.json", {"schema_id": "registry", "zones": []})
    _write_json(governance / "canonical_scope_manifest.json", {"schema_id": "canonical"})
    _write_json(governance / "readiness_scope_manifest.json", {"schema_id": "readiness"})

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")

    with pytest.raises(RuntimeError, match="package promotion must remain deferred"):
        tranche.run(
            reports_root=reports,
            governance_root=governance,
            authority_receipt_path=reports / "cohort0_trust_zone_boundary_purification_authority_receipt.json",
            post_merge_audit_receipt_path=reports / "cohort0_post_merge_canonical_truth_boundary_readiness_audit_receipt.json",
            trust_zone_registry_path=governance / "trust_zone_registry.json",
            canonical_scope_manifest_path=governance / "canonical_scope_manifest.json",
            readiness_scope_manifest_path=governance / "readiness_scope_manifest.json",
        )
