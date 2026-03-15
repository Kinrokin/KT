from __future__ import annotations

import json
from pathlib import Path

from tools.operator.trust_zone_validate import validate_trust_zones


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _seed_governance(root: Path, *, readiness_excludes: list[str]) -> None:
    gov = root / "KT_PROD_CLEANROOM" / "governance"
    v2_docs = root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "docs"
    _write_json(
        gov / "trust_zone_registry.json",
        {
            "schema_id": "kt.governance.trust_zone_registry.v2",
            "zones": [
                {"zone_id": "CANONICAL", "include": ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/**", "KT_PROD_CLEANROOM/governance/**"], "exclude": ["KT_PROD_CLEANROOM/reports/**", "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/tools/**", "KT_PROD_CLEANROOM/05_QUARANTINE/**"]},
                {"zone_id": "LAB", "include": ["KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/**"], "exclude": []},
                {"zone_id": "ARCHIVE", "include": ["KT_ARCHIVE/**"], "exclude": []},
                {"zone_id": "COMMERCIAL", "include": ["docs/**"], "exclude": []},
                {"zone_id": "GENERATED_RUNTIME_TRUTH", "include": ["KT_PROD_CLEANROOM/reports/**", "KT_PROD_CLEANROOM/exports/_truth/**"], "exclude": []},
                {"zone_id": "QUARANTINED", "include": ["KT_PROD_CLEANROOM/05_QUARANTINE/**", "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/tools/**"], "exclude": []},
            ],
        },
    )
    _write_json(
        gov / "canonical_scope_manifest.json",
        {
            "schema_id": "kt.governance.canonical_scope_manifest.v2",
            "canonical_primary_surfaces": ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/**", "KT_PROD_CLEANROOM/governance/**"],
            "generated_truth_surfaces": ["KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json", "KT_PROD_CLEANROOM/reports/settled_truth_source_receipt.json"],
            "documentary_only_surfaces": ["docs/**"],
            "quarantined_from_canonical_truth": ["KT_PROD_CLEANROOM/05_QUARANTINE/**", "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/tools/**"],
        },
    )
    _write_json(
        gov / "readiness_scope_manifest.json",
        {
            "schema_id": "kt.governance.readiness_scope_manifest.v2",
            "readiness_includes_zones": ["CANONICAL"],
            "readiness_excludes_zones": readiness_excludes,
        },
    )
    _write_json(
        gov / "runtime_boundary_contract.json",
        {
            "schema_id": "kt.governance.runtime_boundary_contract.v1",
            "canonical_runtime_roots": ["core", "kt"],
            "compatibility_allowlist_roots": ["tools"],
            "canonical_runtime_excludes": ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/tools/**"],
        },
    )
    _write_json(
        v2_docs / "RUNTIME_REGISTRY.json",
        {
            "schema_id": "kt.runtime_registry.v1",
            "schema_version_hash": "test-only",
            "registry_version": "1",
            "canonical_entry": {"module": "kt.entrypoint", "callable": "invoke"},
            "canonical_spine": {"module": "core.spine", "callable": "run"},
            "state_vault": {"jsonl_path": "_runtime_artifacts/state_vault.jsonl"},
            "runtime_import_roots": ["core", "kt"],
            "compatibility_allowlist_roots": ["tools"],
            "organs_by_root": {"core": "Spine", "kt": "Entry Point"},
            "import_truth_matrix": {"Entry Point": ["Entry Point", "Spine"], "Spine": ["Spine"]},
            "dry_run": {"no_network": True, "providers_enabled": False},
            "policy_c": {"drift": {}, "sweep": {}, "static_safety": {}},
            "adapters": {"registry_schema_id": "kt.adapters.registry.v1", "allowed_export_roots": ["exports/adapters"], "entries": []},
        },
    )
    _write_json(
        gov / "canonical_freeze_manifest.json",
        {
            "schema_id": "kt.governance.canonical_freeze_manifest.v1",
            "frozen_surfaces": ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/**", "KT_PROD_CLEANROOM/governance/**"],
        },
    )
    _write_json(
        gov / "amendment_scope_manifest.json",
        {
            "schema_id": "kt.governance.amendment_scope_manifest.v1",
            "protected_surfaces": ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/**", "KT_PROD_CLEANROOM/governance/**"],
        },
    )
    _write_json(
        gov / "settled_truth_source_contract.json",
        {
            "schema_id": "kt.governance.settled_truth_source_contract.v1",
            "current_head_truth_root": "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
        },
    )
    _write_json(
        gov / "execution_board.json",
        {
            "schema_id": "kt.governance.execution_board.v2",
            "authoritative_current_head_truth_source": "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
        },
    )


def test_validate_trust_zones_passes_for_six_zone_law(tmp_path: Path) -> None:
    _seed_governance(
        tmp_path,
        readiness_excludes=["LAB", "ARCHIVE", "COMMERCIAL", "GENERATED_RUNTIME_TRUTH", "QUARANTINED"],
    )
    report = validate_trust_zones(root=tmp_path)
    assert report["status"] == "PASS", report


def test_validate_trust_zones_fails_when_generated_truth_is_not_excluded_from_readiness(tmp_path: Path) -> None:
    _seed_governance(
        tmp_path,
        readiness_excludes=["LAB", "ARCHIVE", "COMMERCIAL", "QUARANTINED"],
    )
    report = validate_trust_zones(root=tmp_path)
    assert report["status"] == "FAIL"
    assert "readiness_excludes_incomplete" in report["failures"]


def test_validate_trust_zones_fails_when_runtime_registry_keeps_tools_canonical(tmp_path: Path) -> None:
    _seed_governance(
        tmp_path,
        readiness_excludes=["LAB", "ARCHIVE", "COMMERCIAL", "GENERATED_RUNTIME_TRUTH", "QUARANTINED"],
    )
    runtime_registry_path = tmp_path / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "docs" / "RUNTIME_REGISTRY.json"
    runtime_registry = json.loads(runtime_registry_path.read_text(encoding="utf-8"))
    runtime_registry["runtime_import_roots"] = ["core", "kt", "tools"]
    runtime_registry["compatibility_allowlist_roots"] = []
    runtime_registry_path.write_text(json.dumps(runtime_registry, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report = validate_trust_zones(root=tmp_path)

    assert report["status"] == "FAIL"
    assert "runtime_registry_canonical_roots_mismatch" in report["failures"]
