from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from tools.operator.dependency_inventory_emit import build_dependency_reports
from tools.operator.dependency_inventory_reconcile import (
    CURRENT_EVIDENCE_STATUS,
    reconcile_dependency_evidence,
)
from tools.operator.dependency_inventory_validate import build_dependency_inventory_validation_report


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _seed_historical_dependency_reports(root: Path) -> None:
    report_root = root / "KT_PROD_CLEANROOM" / "reports"
    for name, payload in (
        ("dependency_inventory.json", {"schema_id": "historical.inventory", "status": "ARCHIVED"}),
        ("python_environment_manifest.json", {"schema_id": "historical.environment", "status": "ARCHIVED"}),
        ("sbom_cyclonedx.json", {"bomFormat": "CycloneDX", "status": "ARCHIVED"}),
        ("dependency_inventory_validation_receipt.json", {"schema_id": "historical.receipt", "status": "FAIL"}),
    ):
        _write(report_root / name, json.dumps(payload, sort_keys=True) + "\n")


def _init_git(root: Path) -> str:
    for args in (
        ("init",),
        ("add", "."),
        ("-c", "user.name=KT Test", "-c", "user.email=kt-test@example.invalid", "commit", "-m", "seed"),
    ):
        subprocess.run(("git", *args), cwd=root, check=True, capture_output=True, text=True)
    return subprocess.run(
        ("git", "rev-parse", "HEAD"), cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


def _seed_reconciliation_source(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "source"
    _write(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src" / "sample.py", "import json\n")
    _seed_historical_dependency_reports(root)
    return root, _init_git(root)


def test_dependency_inventory_classifies_modules(tmp_path: Path) -> None:
    _write(tmp_path / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src" / "my_module.py", "import json\nimport numpy\nfrom tools.operator import x\n")
    _write(tmp_path / "KT_PROD_CLEANROOM" / "tools" / "operator" / "x.py", "import pathlib\n")

    reports = build_dependency_reports(
        root=tmp_path,
        scan_roots=(
            "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src",
            "KT_PROD_CLEANROOM/tools/operator",
        ),
    )
    stdlib = {row["module"] for row in reports["inventory"]["stdlib_modules"]}
    first_party = {row["module"] for row in reports["inventory"]["first_party_modules"]}
    third_party = {row["module"] for row in reports["inventory"]["third_party_modules"]}

    assert "json" in stdlib
    assert "pathlib" in stdlib
    assert "tools" in first_party
    assert "numpy" in third_party


def test_dependency_inventory_validation_matches_generated_files(tmp_path: Path) -> None:
    _write(tmp_path / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src" / "sample.py", "import json\n")
    reports = build_dependency_reports(root=tmp_path)
    report_root = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    report_root.mkdir(parents=True, exist_ok=True)
    for name, payload in (
        ("dependency_inventory.json", reports["inventory"]),
        ("python_environment_manifest.json", reports["environment"]),
        ("sbom_cyclonedx.json", reports["sbom"]),
    ):
        (report_root / name).write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    report = build_dependency_inventory_validation_report(root=tmp_path, report_root=report_root)
    assert report["status"] == "PASS"




def test_dependency_emission_rejects_ignored_python_under_scan_root(tmp_path: Path) -> None:
    root, _ = _seed_reconciliation_source(tmp_path)
    ignored = root / "KT_PROD_CLEANROOM" / "tools" / "operator" / "ignored_extra.py"
    _write(ignored, "import json\n")
    _write(root / ".gitignore", "KT_PROD_CLEANROOM/tools/operator/ignored_extra.py\n")
    subprocess.run(("git", "add", ".gitignore"), cwd=root, check=True, capture_output=True)
    subprocess.run(("git", "-c", "user.name=KT Test", "-c", "user.email=kt-test@example.invalid", "commit", "-m", "ignore extra source"), cwd=root, check=True, capture_output=True)
    from tools.operator.dependency_inventory_emit import emit_dependency_reports
    with pytest.raises(RuntimeError, match="DEPENDENCY_SOURCE_SCAN_ROOT_UNTRACKED_OR_IGNORED"):
        emit_dependency_reports(root=root, report_root=tmp_path / "external")


def test_dependency_reconciliation_emits_current_external_evidence_without_touching_history(tmp_path: Path) -> None:
    root, head = _seed_reconciliation_source(tmp_path)
    historical_paths = tuple((root / "KT_PROD_CLEANROOM" / "reports").glob("*.json"))
    before = {path.name: _sha256(path) for path in historical_paths}

    evidence_root = tmp_path / "external-evidence"
    receipt = reconcile_dependency_evidence(root=root, report_root=evidence_root)

    assert receipt["status"] == CURRENT_EVIDENCE_STATUS
    assert receipt["validation_status"] == "PASS"
    assert receipt["current_head"] == head
    assert receipt["historical_reports_retained"] is True
    assert {path.name: _sha256(path) for path in historical_paths} == before
    for name in (
        "dependency_inventory.json",
        "python_environment_manifest.json",
        "sbom_cyclonedx.json",
        "dependency_inventory_validation_receipt.json",
        "dependency_inventory_reconciliation_receipt.json",
    ):
        assert (evidence_root / name).is_file()


def test_dependency_reconciliation_rejects_repository_output_root(tmp_path: Path) -> None:
    root, _ = _seed_reconciliation_source(tmp_path)
    with pytest.raises(ValueError, match="DEPENDENCY_REPORT_ROOT_MUST_BE_EXTERNAL"):
        reconcile_dependency_evidence(root=root, report_root=root / "outside")
    assert not (root / "outside").exists()


def test_dependency_reconciliation_refuses_existing_external_output_root(tmp_path: Path) -> None:
    root, _ = _seed_reconciliation_source(tmp_path)
    evidence_root = tmp_path / "external-evidence"
    evidence_root.mkdir()
    with pytest.raises(FileExistsError, match="DEPENDENCY_REPORT_ROOT_ALREADY_EXISTS"):
        reconcile_dependency_evidence(root=root, report_root=evidence_root)


def test_dependency_reconciliation_refuses_dirty_source_bytes(tmp_path: Path) -> None:
    root, _ = _seed_reconciliation_source(tmp_path)
    _write(root / "untracked.py", "import json\n")
    evidence_root = tmp_path / "external-evidence"
    with pytest.raises(RuntimeError, match="DEPENDENCY_SOURCE_WORKTREE_NOT_CLEAN"):
        reconcile_dependency_evidence(root=root, report_root=evidence_root)
    assert not evidence_root.exists()


def test_reconcile_rejects_symlinked_historical_report_root(tmp_path: Path) -> None:
    root = tmp_path / "source"
    (root / "KT_PROD_CLEANROOM").mkdir(parents=True)
    external = tmp_path / "external-reports"
    external.mkdir()
    (root / "KT_PROD_CLEANROOM" / "reports").symlink_to(external, target_is_directory=True)
    _init_git(root)
    with pytest.raises(RuntimeError, match="HISTORICAL_DEPENDENCY_REPORT_SYMLINK_FORBIDDEN"):
        reconcile_dependency_evidence(root=root, report_root=tmp_path / "current")



