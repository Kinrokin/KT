from __future__ import annotations

import json
from pathlib import Path

from tools.operator.dependency_inventory_emit import build_dependency_reports
from tools.operator.dependency_inventory_validate import build_dependency_inventory_validation_report


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


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
    reports = build_dependency_reports(root=tmp_path, scan_roots=("KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src",))
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
