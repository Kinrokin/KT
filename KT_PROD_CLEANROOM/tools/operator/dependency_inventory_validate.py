from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.dependency_inventory_emit import DEFAULT_SCAN_ROOTS, build_dependency_reports, resolve_external_report_root
from tools.operator.titanium_common import make_run_dir, repo_root, write_failure_artifacts, write_json_worm


def _load_json(path: Path) -> Dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: required artifact must be a regular file: {path.as_posix()}")
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
    declared_scan_roots = actual_inventory.get("scan_roots")
    if (
        not isinstance(declared_scan_roots, list)
        or not declared_scan_roots
        or any(type(item) is not str or item not in DEFAULT_SCAN_ROOTS for item in declared_scan_roots)
        or len(set(declared_scan_roots)) != len(declared_scan_roots)
        or set(declared_scan_roots) != set(DEFAULT_SCAN_ROOTS)
    ):
        raise RuntimeError("DEPENDENCY_SCAN_ROOTS_INVALID")
    expected = build_dependency_reports(root=root, scan_roots=tuple(declared_scan_roots))

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
    ap.add_argument(
        "--report-root",
        required=True,
        help="absolute external evidence root emitted for this current-head validation",
    )
    ap.add_argument(
        "--run-root",
        required=True,
        help="absolute external validation-output root; repository paths are rejected",
    )
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    run_dir: Optional[Path] = None
    try:
        report_root = resolve_external_report_root(root=root, report_root=args.report_root)
        run_root = resolve_external_report_root(root=root, report_root=args.run_root)
        run_dir = make_run_dir(cmd_name="dependency-inventory-validate", requested_run_root=str(run_root))
        status = subprocess.run(("git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"), check=True, capture_output=True, text=True).stdout
        if status.strip():
            raise RuntimeError("DEPENDENCY_SOURCE_WORKTREE_NOT_CLEAN")
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
        if run_dir is None:
            print(json.dumps({"failure": str(exc), "status": "FAIL"}, sort_keys=True, ensure_ascii=True))
            return 2
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.dependency.inventory.validate",
            failure_name="DEPENDENCY_INVENTORY_INVALID",
            message=str(exc),
            next_actions=["Inspect dependency_inventory.json, python_environment_manifest.json, and sbom_cyclonedx.json."],
        )


if __name__ == "__main__":
    raise SystemExit(main())
