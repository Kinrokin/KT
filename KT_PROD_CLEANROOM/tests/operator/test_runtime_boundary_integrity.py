from __future__ import annotations

import json
import subprocess
from pathlib import Path

from tools.operator.runtime_boundary_integrity import (
    RUNTIME_BOUNDARY_HEAD_VERDICT_CONTAINS,
    RUNTIME_BOUNDARY_VERDICT_SETTLED,
    build_runtime_boundary_claims,
    build_runtime_boundary_integrity_receipt,
    build_runtime_boundary_report,
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _seed_boundary_inputs(root: Path) -> None:
    _write_json(
        root / "KT_PROD_CLEANROOM" / "governance" / "runtime_boundary_contract.json",
        {
            "schema_id": "kt.governance.runtime_boundary_contract.v1",
            "contract_id": "RUNTIME_BOUNDARY_CONTRACT_TEST",
            "canonical_runtime_roots": ["core", "kt"],
            "compatibility_allowlist_roots": ["tools"],
            "canonical_runtime_excludes": ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/tools/**"],
        },
    )
    _write_json(
        root / "KT_PROD_CLEANROOM" / "governance" / "canonical_scope_manifest.json",
        {
            "schema_id": "kt.governance.canonical_scope_manifest.v2",
            "quarantined_from_canonical_truth": ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/tools/**"],
        },
    )
    _write_json(
        root / "KT_PROD_CLEANROOM" / "governance" / "trust_zone_registry.json",
        {
            "schema_id": "kt.governance.trust_zone_registry.v2",
            "zones": [
                {
                    "zone_id": "CANONICAL",
                    "include": ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/**"],
                    "exclude": ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/tools/**"],
                },
                {
                    "zone_id": "QUARANTINED",
                    "include": ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/tools/**"],
                    "exclude": [],
                },
            ],
        },
    )
    _write_json(
        root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "docs" / "RUNTIME_REGISTRY.json",
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


def _git(tmp_path: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(tmp_path), *args], text=True).strip()


def _commit_all(tmp_path: Path, message: str) -> str:
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", message)
    return _git(tmp_path, "rev-parse", "HEAD")


def _init_git_repo(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test User")


def test_runtime_boundary_integrity_receipt_passes_for_quarantined_compatibility_root(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    (tmp_path / "README.md").write_text("base\n", encoding="utf-8")
    _seed_boundary_inputs(tmp_path)
    head_sha = _commit_all(tmp_path, "seed")

    receipt = build_runtime_boundary_integrity_receipt(root=tmp_path)

    assert receipt["status"] == "PASS"
    assert receipt["runtime_boundary_verdict"] == RUNTIME_BOUNDARY_VERDICT_SETTLED
    assert receipt["runtime_boundary_subject_commit"] == head_sha
    assert receipt["compatibility_allowlist_roots"] == ["tools"]


def test_runtime_boundary_integrity_receipt_fail_closes_when_tools_remain_canonical(tmp_path: Path) -> None:
    _seed_boundary_inputs(tmp_path)
    registry_path = tmp_path / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "docs" / "RUNTIME_REGISTRY.json"
    payload = json.loads(registry_path.read_text(encoding="utf-8"))
    payload["runtime_import_roots"] = ["core", "kt", "tools"]
    payload["compatibility_allowlist_roots"] = []
    _write_json(registry_path, payload)

    receipt = build_runtime_boundary_integrity_receipt(root=tmp_path)

    assert receipt["status"] == "FAIL"
    assert "runtime_registry_canonical_roots_mismatch" in receipt["failures"]


def test_runtime_boundary_report_fail_closes_head_to_contains_evidence(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    (tmp_path / "README.md").write_text("base\n", encoding="utf-8")
    _commit_all(tmp_path, "base")

    receipt_path = tmp_path / "KT_PROD_CLEANROOM" / "reports" / "runtime_boundary_integrity_receipt.json"
    _write_json(
        receipt_path,
        {
            "schema_id": "kt.operator.runtime_boundary_integrity_receipt.v1",
            "status": "PASS",
            "runtime_boundary_subject_commit": "b" * 40,
            "runtime_boundary_verdict": RUNTIME_BOUNDARY_VERDICT_SETTLED,
            "runtime_boundary_claim_admissible": True,
            "runtime_boundary_claim_boundary": "boundary settled",
            "canonical_runtime_roots": ["core", "kt"],
            "compatibility_allowlist_roots": ["tools"],
        },
    )
    evidence_commit = _commit_all(tmp_path, "runtime boundary evidence")

    (tmp_path / "later.txt").write_text("head drift\n", encoding="utf-8")
    current_head = _commit_all(tmp_path, "later change")

    claims = build_runtime_boundary_claims(root=tmp_path)
    report = build_runtime_boundary_report(root=tmp_path)

    assert claims["runtime_boundary_evidence_commit"] == evidence_commit
    assert report["current_head_commit"] == current_head
    assert report["runtime_boundary_subject_commit"] == "b" * 40
    assert report["runtime_boundary_head_equals_subject"] is False
    assert report["runtime_boundary_head_claim_verdict"] == RUNTIME_BOUNDARY_HEAD_VERDICT_CONTAINS
