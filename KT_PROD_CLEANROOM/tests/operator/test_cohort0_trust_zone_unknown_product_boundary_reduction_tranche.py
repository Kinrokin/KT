from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_trust_zone_unknown_product_boundary_reduction_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_inputs(root: Path) -> tuple[Path, Path]:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    governance = root / "KT_PROD_CLEANROOM" / "governance"
    _write_json(
        reports / tranche.MATERIALIZATION_RECEIPT,
        {
            "schema_id": "materialization",
            "status": "PASS",
            "next_lawful_move": "REDUCE_UNKNOWN_ZONE_INVENTORY_AND_REVIEW_PRODUCT_PROOF_BOUNDARIES",
            "package_promotion_remains_deferred": True,
        },
    )
    _write_json(
        reports / tranche.UNKNOWN_ZONE_RESOLUTION_QUEUE,
        {
            "schema_id": "queue",
            "status": "PASS",
            "queue_count": 4,
            "entries": [
                {"queue_id": "UZQ-0001", "path": "KT_PROD_CLEANROOM/docs/operator/RUNBOOK.md", "suggested_zone": "CANONICAL"},
                {"queue_id": "UZQ-0002", "path": "KT_PROD_CLEANROOM/tests/fl3/test_x.py", "suggested_zone": "UNKNOWN_REQUIRES_HUMAN_REVIEW"},
                {"queue_id": "UZQ-0003", "path": "KT_PROD_CLEANROOM/tests/conftest.py", "suggested_zone": "UNKNOWN_REQUIRES_HUMAN_REVIEW"},
                {"queue_id": "UZQ-0004", "path": "KT_PROD_CLEANROOM/EXECUTION_DAG_POST_WAVE5_V1.md", "suggested_zone": "UNKNOWN_REQUIRES_HUMAN_REVIEW"},
            ],
        },
    )
    _write_json(
        reports / tranche.PRODUCT_PROOF_BLOCKER_LEDGER,
        {
            "schema_id": "product-ledger",
            "status": "PASS",
            "ledger_entries": [
                {"ledger_id": "PPB-001", "path": "KT_PROD_CLEANROOM/docs/commercial/E1_BOUNDED_TRUST_WEDGE.md", "line": 22, "terms": ["sota"]},
                {"ledger_id": "PPB-002", "path": "docs/generated/kt_master_spec.md", "line": 6, "terms": ["frontier"]},
            ],
        },
    )
    _write_json(reports / tranche.COMMERCIAL_BOUNDARY_REVIEW_PACKET, {"schema_id": "commercial", "status": "PASS", "review_queue_count": 2})
    _write_json(
        governance / "trust_zone_registry.json",
        {
            "schema_id": "registry",
            "registry_id": "REG",
            "zones": [
                {
                    "zone_id": "CANONICAL",
                    "include": ["KT_PROD_CLEANROOM/docs/operator/**", "KT_PROD_CLEANROOM/governance/**"],
                    "exclude": ["KT_PROD_CLEANROOM/docs/**"],
                },
                {"zone_id": "TOOLCHAIN_PROVING", "include": ["KT_PROD_CLEANROOM/tools/operator/**"], "exclude": []},
                {"zone_id": "QUARANTINED", "include": ["KT_PROD_CLEANROOM/05_QUARANTINE/**"], "exclude": []},
            ],
        },
    )
    _write_json(
        governance / "canonical_scope_manifest.json",
        {
            "schema_id": "canonical",
            "manifest_id": "CANON",
            "excluded_from_canonical_truth": ["KT_PROD_CLEANROOM/docs/**"],
            "toolchain_proving_surfaces": [],
        },
    )
    return reports, governance


def test_reduces_unknown_queue_and_reviews_product_boundaries(tmp_path: Path, monkeypatch) -> None:
    reports, governance = _write_inputs(tmp_path)
    tracked = [
        "KT_PROD_CLEANROOM/docs/operator/RUNBOOK.md",
        "KT_PROD_CLEANROOM/tests/fl3/test_x.py",
        "KT_PROD_CLEANROOM/tests/conftest.py",
        "KT_PROD_CLEANROOM/tests/test_resolver.py",
        "KT_PROD_CLEANROOM/tools/__init__.py",
        "KT_PROD_CLEANROOM/EXECUTION_DAG_POST_WAVE5_V1.md",
        "run_kt_e2e.sh",
    ]

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche.common, "git_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche.common, "git_rev_parse", lambda root, ref: "abc123")
    monkeypatch.setattr(tranche.common, "git_ls_files", lambda root: tracked)
    monkeypatch.setattr(tranche, "validate_trust_zones", lambda root: {"schema_id": "validation", "status": "PASS", "checks": [{"check": "ok"}], "failures": []})

    result = tranche.run(
        reports_root=reports,
        governance_root=governance,
        materialization_receipt_path=reports / tranche.MATERIALIZATION_RECEIPT,
        unknown_queue_path=reports / tranche.UNKNOWN_ZONE_RESOLUTION_QUEUE,
        product_ledger_path=reports / tranche.PRODUCT_PROOF_BLOCKER_LEDGER,
        commercial_review_path=reports / tranche.COMMERCIAL_BOUNDARY_REVIEW_PACKET,
        trust_zone_registry_path=governance / "trust_zone_registry.json",
        canonical_scope_manifest_path=governance / "canonical_scope_manifest.json",
    )

    assert result["outcome"] == tranche.OUTCOME
    registry = _load(governance / "trust_zone_registry.json")
    scope = _load(governance / "canonical_scope_manifest.json")
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)
    queue = _load(reports / tranche.UNKNOWN_ZONE_RESOLUTION_QUEUE)
    product = _load(reports / tranche.PRODUCT_PROOF_REVIEW_RECEIPT)
    buyer_patch = _load(reports / tranche.BUYER_SAFE_LANGUAGE_PATCH_QUEUE)

    canonical = next(row for row in registry["zones"] if row["zone_id"] == "CANONICAL")
    assert "KT_PROD_CLEANROOM/docs/**" not in canonical["exclude"]
    assert "KT_PROD_CLEANROOM/tests/fl3/**" in next(row for row in registry["zones"] if row["zone_id"] == "TOOLCHAIN_PROVING")["include"]
    assert "KT_PROD_CLEANROOM/EXECUTION_DAG_POST_WAVE5_V1.md" in next(row for row in registry["zones"] if row["zone_id"] == "QUARANTINED")["include"]
    assert "KT_PROD_CLEANROOM/docs/operator/**" in scope["canonical_support_surfaces"]
    assert receipt["unknown_queue_before"] == 4
    assert receipt["unknown_queue_after"] == 0
    assert queue["queue_count"] == 0
    assert product["resolved_count"] == 1
    assert product["deferred_count"] == 1
    assert buyer_patch["patch_required_count"] == 1


def test_reduction_requires_materialization_authorization(tmp_path: Path, monkeypatch) -> None:
    reports, governance = _write_inputs(tmp_path)
    _write_json(
        reports / tranche.MATERIALIZATION_RECEIPT,
        {
            "schema_id": "materialization",
            "status": "PASS",
            "next_lawful_move": "SOMETHING_ELSE",
            "package_promotion_remains_deferred": True,
        },
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche.common, "git_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche.common, "git_status_porcelain", lambda root: "")

    with pytest.raises(RuntimeError, match="authorize unknown-zone reduction"):
        tranche.run(
            reports_root=reports,
            governance_root=governance,
            materialization_receipt_path=reports / tranche.MATERIALIZATION_RECEIPT,
            unknown_queue_path=reports / tranche.UNKNOWN_ZONE_RESOLUTION_QUEUE,
            product_ledger_path=reports / tranche.PRODUCT_PROOF_BLOCKER_LEDGER,
            commercial_review_path=reports / tranche.COMMERCIAL_BOUNDARY_REVIEW_PACKET,
            trust_zone_registry_path=governance / "trust_zone_registry.json",
            canonical_scope_manifest_path=governance / "canonical_scope_manifest.json",
        )
