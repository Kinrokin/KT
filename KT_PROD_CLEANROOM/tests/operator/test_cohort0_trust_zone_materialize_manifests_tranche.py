from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_trust_zone_materialize_manifests_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_inputs(root: Path) -> tuple[Path, Path]:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    governance = root / "KT_PROD_CLEANROOM" / "governance"
    _write_json(
        reports / tranche.CONTRACT_RECEIPT,
        {
            "schema_id": "contract",
            "status": "PASS",
            "next_lawful_move": "EXECUTE_TRUST_ZONE_BOUNDARY_PURIFICATION_PARALLEL_PREP_BUNDLE",
            "package_promotion_remains_deferred": True,
        },
    )
    _write_json(
        reports / tranche.PREP_RECEIPT,
        {
            "schema_id": "prep",
            "status": "PASS",
            "next_lawful_move": "MATERIALIZE_TRUST_ZONE_REGISTRY_SCOPE_MANIFESTS_AND_QUARANTINE_RECEIPT",
            "unknown_zone_path_count": 2,
            "candidate_commercial_violation_count": 1,
            "package_promotion_remains_deferred": True,
        },
    )
    _write_json(
        governance / "trust_zone_registry.json",
        {
            "schema_id": "kt.governance.trust_zone_registry.v2",
            "registry_id": "REG",
            "zones": [
                {"zone_id": "CANONICAL", "include": ["KT_PROD_CLEANROOM/governance/**"], "exclude": []},
                {"zone_id": "COMMERCIAL", "include": ["README.md", "docs/**"], "exclude": []},
                {"zone_id": "TOOLCHAIN_PROVING", "include": ["KT_PROD_CLEANROOM/tools/operator/**"], "exclude": []},
                {"zone_id": "GENERATED_RUNTIME_TRUTH", "include": ["KT_PROD_CLEANROOM/reports/**"], "exclude": []},
                {"zone_id": "QUARANTINED", "include": ["KT_PROD_CLEANROOM/05_QUARANTINE/**"], "exclude": []},
            ],
        },
    )
    _write_json(governance / "canonical_scope_manifest.json", {"schema_id": "canonical", "manifest_id": "CANON"})
    _write_json(governance / "readiness_scope_manifest.json", {"schema_id": "readiness", "manifest_id": "READY"})
    _write_json(
        reports / "product_proof_conflation_scan.json",
        {
            "schema_id": "scan",
            "status": "PASS",
            "findings": [{"path": "README.md", "line": 1, "terms": ["frontier"], "snippet": "frontier"}],
        },
    )
    _write_json(
        reports / "commercial_claim_boundary_violations.json",
        {
            "schema_id": "violations",
            "status": "PASS",
            "candidate_violations": [{"path": "README.md", "line": 1, "terms": ["frontier"], "candidate_violation_class": "risky_claim_boundary_review"}],
        },
    )
    return reports, governance


def test_materializes_manifests_queue_and_quarantine_receipts(tmp_path: Path, monkeypatch) -> None:
    reports, governance = _write_inputs(tmp_path)

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche.common, "git_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche.common, "git_rev_parse", lambda root, ref: "abc123")
    monkeypatch.setattr(
        tranche.common,
        "git_ls_files",
        lambda root: [
            "README.md",
            "KT_PROD_CLEANROOM/governance/trust_zone_registry.json",
            "KT_PROD_CLEANROOM/product/client_wrapper_spec.json",
            "KT_PROD_CLEANROOM/runs/post_f_track_03/run-x/artifacts/receipt.json",
            "misc/unknown.txt",
        ],
    )
    monkeypatch.setattr(tranche, "validate_trust_zones", lambda root: {"schema_id": "validation", "status": "PASS", "checks": [{"check": "ok"}], "failures": []})

    result = tranche.run(
        reports_root=reports,
        governance_root=governance,
        contract_receipt_path=reports / tranche.CONTRACT_RECEIPT,
        prep_receipt_path=reports / tranche.PREP_RECEIPT,
        trust_zone_registry_path=governance / "trust_zone_registry.json",
        canonical_scope_manifest_path=governance / "canonical_scope_manifest.json",
        readiness_scope_manifest_path=governance / "readiness_scope_manifest.json",
        product_scan_path=reports / "product_proof_conflation_scan.json",
        commercial_violations_path=reports / "commercial_claim_boundary_violations.json",
    )

    assert result["outcome"] == tranche.OUTCOME
    registry = _load(governance / "trust_zone_registry.json")
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)
    queue = _load(reports / tranche.UNKNOWN_ZONE_RESOLUTION_QUEUE)
    product_ledger = _load(reports / tranche.PRODUCT_PROOF_BLOCKER_LEDGER)
    commercial_review = _load(reports / tranche.COMMERCIAL_BOUNDARY_REVIEW_PACKET)
    quarantine = _load(reports / tranche.NONCANONICAL_QUARANTINE_RECEIPT)
    validation = _load(reports / tranche.TRUST_ZONE_VALIDATION_MATRIX)

    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE
    assert receipt["package_promotion_remains_deferred"] is True
    assert "KT_PROD_CLEANROOM/tests/operator/**" in next(row for row in registry["zones"] if row["zone_id"] == "TOOLCHAIN_PROVING")["include"]
    assert "KT_PROD_CLEANROOM/product/**" in next(row for row in registry["zones"] if row["zone_id"] == "COMMERCIAL")["include"]
    assert queue["queue_count"] == 1
    assert queue["suggested_zone_counts"]["UNKNOWN_REQUIRES_HUMAN_REVIEW"] == 1
    assert product_ledger["candidate_violation_count"] == 1
    assert product_ledger["live_blocker_count"] == 0
    assert commercial_review["review_queue_count"] == 1
    assert quarantine["outcome"] == "NONCANONICAL_QUARANTINE_RECEIPT_MATERIALIZED__NO_LIVE_MUTATION"
    assert validation["validation_status"] == "PASS"


def test_materialization_requires_prep_authorization(tmp_path: Path, monkeypatch) -> None:
    reports, governance = _write_inputs(tmp_path)
    _write_json(
        reports / tranche.PREP_RECEIPT,
        {
            "schema_id": "prep",
            "status": "PASS",
            "next_lawful_move": "SOMETHING_ELSE",
            "package_promotion_remains_deferred": True,
        },
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche.common, "git_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche.common, "git_status_porcelain", lambda root: "")

    with pytest.raises(RuntimeError, match="authorize trust-zone manifest materialization"):
        tranche.run(
            reports_root=reports,
            governance_root=governance,
            contract_receipt_path=reports / tranche.CONTRACT_RECEIPT,
            prep_receipt_path=reports / tranche.PREP_RECEIPT,
            trust_zone_registry_path=governance / "trust_zone_registry.json",
            canonical_scope_manifest_path=governance / "canonical_scope_manifest.json",
            readiness_scope_manifest_path=governance / "readiness_scope_manifest.json",
            product_scan_path=reports / "product_proof_conflation_scan.json",
            commercial_violations_path=reports / "commercial_claim_boundary_violations.json",
        )
