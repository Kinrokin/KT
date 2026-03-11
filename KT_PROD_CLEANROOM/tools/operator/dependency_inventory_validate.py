from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.dependency_inventory_emit import DEFAULT_REPORT_ROOT_REL, build_dependency_reports
from tools.operator.titanium_common import make_run_dir, repo_root, write_failure_artifacts, write_json_worm


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {path.as_posix()}")
    return json.loads(path.read_text(encoding="utf-8"))


def _normalized(payload: Dict[str, Any]) -> Dict[str, Any]:
    clone = json.loads(json.dumps(payload))
    clone.pop("generated_utc", None)
    metadata = clone.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("timestamp", None)
    return clone


def build_dependency_inventory_validation_report(*, root: Path, report_root: Path) -> Dict[str, Any]:
    actual_inventory = _load_json(report_root / "dependency_inventory.json")
    actual_environment = _load_json(report_root / "python_environment_manifest.json")
    actual_sbom = _load_json(report_root / "sbom_cyclonedx.json")
    scan_roots = tuple(str(item) for item in actual_inventory.get("scan_roots", []) if str(item).strip())
    expected = build_dependency_reports(root=root, scan_roots=scan_roots) if scan_roots else build_dependency_reports(root=root)

    checks = []
    failures = []

    for check_id, actual, wanted in (
        ("dependency_inventory_matches", actual_inventory, expected["inventory"]),
        ("python_environment_manifest_matches", actual_environment, expected["environment"]),
        ("sbom_cyclonedx_matches", actual_sbom, expected["sbom"]),
    ):
        ok = _normalized(actual) == _normalized(wanted)
        checks.append({"check": check_id, "status": "PASS" if ok else "FAIL"})
        if not ok:
            failures.append(check_id)

    return {
        "schema_id": "kt.operator.dependency_inventory_validation_receipt.v1",
        "status": "PASS" if not failures else "FAIL",
        "checks": checks,
        "failures": failures,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Validate dependency inventory, environment manifest, and SBOM preview.")
    ap.add_argument("--report-root", default=DEFAULT_REPORT_ROOT_REL)
    ap.add_argument("--run-root", default="")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    run_dir = make_run_dir(cmd_name="dependency-inventory-validate", requested_run_root=str(args.run_root))
    try:
        root = repo_root()
        report_root = Path(str(args.report_root)).expanduser()
        if not report_root.is_absolute():
            report_root = (root / report_root).resolve()
        report = build_dependency_inventory_validation_report(root=root, report_root=report_root)
        write_json_worm(run_dir / "reports" / "dependency_inventory_validation_receipt.json", report, label="dependency_inventory_validation_receipt.json")
        if report["status"] != "PASS":
            return write_failure_artifacts(
                run_dir=run_dir,
                program_id="program.dependency.inventory.validate",
                failure_name="DEPENDENCY_INVENTORY_INVALID",
                message="; ".join(report.get("failures", [])),
                next_actions=[
                    "Regenerate dependency inventory, environment manifest, and SBOM preview from the current head.",
                    "Do not claim dependency integrity evidence until the validation receipt passes.",
                ],
            )
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.dependency.inventory.validate",
            failure_name="DEPENDENCY_INVENTORY_INVALID",
            message=str(exc),
            next_actions=["Inspect dependency_inventory.json, python_environment_manifest.json, and sbom_cyclonedx.json."],
        )


if __name__ == "__main__":
    raise SystemExit(main())
