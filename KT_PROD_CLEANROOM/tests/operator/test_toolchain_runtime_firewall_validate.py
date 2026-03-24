from __future__ import annotations

import json
from pathlib import Path

from tools.operator.toolchain_runtime_firewall_validate import build_toolchain_runtime_firewall_receipt


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _seed_firewall_repo(root: Path, *, runtime_import_line: str = "print('ok')\n") -> None:
    gov = root / "KT_PROD_CLEANROOM" / "governance"
    src = root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src"
    docs = root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "docs"
    (src / "core").mkdir(parents=True, exist_ok=True)
    (src / "kt").mkdir(parents=True, exist_ok=True)
    (root / "KT_PROD_CLEANROOM" / "tools" / "operator").mkdir(parents=True, exist_ok=True)
    (src / "core" / "__init__.py").write_text("", encoding="utf-8")
    (src / "kt" / "__init__.py").write_text("", encoding="utf-8")
    (src / "core" / "runtime_only.py").write_text(runtime_import_line, encoding="utf-8")
    _write_json(
        gov / "trust_zone_registry.json",
        {
            "schema_id": "kt.governance.trust_zone_registry.v2",
            "zones": [
                {"zone_id": "CANONICAL", "include": ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/**", "KT_PROD_CLEANROOM/governance/**"], "exclude": ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/tools/**"]},
                {"zone_id": "LAB", "include": ["KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/**"], "exclude": []},
                {"zone_id": "ARCHIVE", "include": ["KT_ARCHIVE/**"], "exclude": []},
                {"zone_id": "COMMERCIAL", "include": ["docs/**"], "exclude": []},
                {"zone_id": "TOOLCHAIN_PROVING", "include": ["KT_PROD_CLEANROOM/tools/operator/**", "ci/**"], "exclude": []},
                {"zone_id": "GENERATED_RUNTIME_TRUTH", "include": ["KT_PROD_CLEANROOM/reports/**"], "exclude": []},
                {"zone_id": "QUARANTINED", "include": ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/tools/**"], "exclude": []},
            ],
        },
    )
    _write_json(
        gov / "canonical_scope_manifest.json",
        {
            "schema_id": "kt.governance.canonical_scope_manifest.v2",
            "canonical_primary_surfaces": ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/**", "KT_PROD_CLEANROOM/governance/**"],
            "toolchain_proving_surfaces": ["KT_PROD_CLEANROOM/tools/operator/**", "ci/**"],
        },
    )
    _write_json(
        gov / "runtime_boundary_contract.json",
        {
            "schema_id": "kt.governance.runtime_boundary_contract.v1",
            "contract_id": "TEST",
            "canonical_runtime_roots": ["core", "kt"],
            "compatibility_allowlist_roots": [],
            "canonical_runtime_excludes": ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/tools/**"],
            "negative_space_exceptions": [
                "repo-level KT_PROD_CLEANROOM/tools/** imports are TOOLCHAIN_PROVING-only and must never be treated as canonical runtime imports or runtime truth"
            ],
        },
    )
    _write_json(
        docs / "RUNTIME_REGISTRY.json",
        {
            "schema_id": "kt.runtime_registry.v1",
            "schema_version_hash": "test-only",
            "registry_version": "1",
            "canonical_entry": {"module": "kt.entrypoint", "callable": "invoke"},
            "canonical_spine": {"module": "core.spine", "callable": "run"},
            "state_vault": {"jsonl_path": "_runtime_artifacts/state_vault.jsonl"},
            "runtime_import_roots": ["core", "kt"],
            "compatibility_allowlist_roots": [],
            "organs_by_root": {"core": "Spine", "kt": "Entry Point"},
            "import_truth_matrix": {"Entry Point": ["Entry Point", "Spine"], "Spine": ["Spine"]},
            "dry_run": {"no_network": True, "providers_enabled": False},
            "policy_c": {"drift": {}, "sweep": {}, "static_safety": {}},
            "adapters": {"registry_schema_id": "kt.adapters.registry.v1", "allowed_export_roots": ["exports/adapters"], "entries": []},
        },
    )


def test_toolchain_runtime_firewall_passes_for_narrowed_toolchain_zone(tmp_path: Path) -> None:
    _seed_firewall_repo(tmp_path)
    receipt = build_toolchain_runtime_firewall_receipt(root=tmp_path)
    assert receipt["status"] == "PASS", receipt


def test_toolchain_runtime_firewall_fails_when_runtime_imports_tools(tmp_path: Path) -> None:
    _seed_firewall_repo(tmp_path, runtime_import_line="import tools.operator.claim_compiler\n")
    receipt = build_toolchain_runtime_firewall_receipt(root=tmp_path)
    assert receipt["status"] == "FAIL"
    assert "runtime_imports_toolchain_proving_surface" in receipt["failures"]
