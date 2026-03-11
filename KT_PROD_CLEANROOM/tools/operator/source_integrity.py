from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.hashpin import _registry_path, _resolve_repo_path
from tools.operator.titanium_common import load_json, make_run_dir, repo_root, utc_now_iso_z, write_failure_artifacts, write_json_worm


def _collect_required_paths(root: Path) -> List[str]:
    registry = load_json(_registry_path(root))
    paths: List[str] = [
        "KT_PROD_CLEANROOM/governance/governance_manifest.json",
        "KT_PROD_CLEANROOM/governance/program_catalog.json",
        "ci/gates/p0_gate_definitions.json",
    ]
    targets = registry.get("targets", {})
    if isinstance(targets, dict):
        for cfg in targets.values():
            if not isinstance(cfg, dict):
                continue
            if "path" in cfg:
                paths.append(str(cfg["path"]))
            if "locator_path" in cfg:
                locator_rel = str(cfg["locator_path"])
                paths.append(locator_rel)
                locator_obj = load_json(_resolve_repo_path(root, locator_rel))
                files = locator_obj.get("files")
                if isinstance(files, list):
                    for file_rel in files:
                        paths.append(str(file_rel))
    return sorted(set(paths))


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=str(root), text=True).strip()


def _verify_source_integrity() -> Dict[str, Any]:
    root = repo_root()
    checked: List[Dict[str, Any]] = []
    failures: List[str] = []
    for rel in _collect_required_paths(root):
        path = _resolve_repo_path(root, rel)
        entry: Dict[str, Any] = {"path": rel.replace("\\", "/"), "status": "PASS"}
        if path.suffix.lower() == ".json":
            try:
                load_json(path)
            except Exception as exc:  # noqa: BLE001
                entry["status"] = "FAIL"
                entry["error"] = str(exc)
                failures.append(f"{rel}:json_invalid")
        if path.stat().st_size == 0:
            entry["status"] = "FAIL"
            entry["error"] = "empty_file"
            failures.append(f"{rel}:empty")
        checked.append(entry)
    return {
        "schema_id": "kt.operator.source_integrity_report.v1",
        "generated_utc": utc_now_iso_z(),
        "branch_ref": _git(root, "rev-parse", "--abbrev-ref", "HEAD"),
        "validated_head_sha": _git(root, "rev-parse", "HEAD"),
        "checked": checked,
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="KT source integrity verification.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ap_verify = sub.add_parser("verify")
    ap_verify.add_argument("--run-root", default="")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    run_dir = make_run_dir(cmd_name="source-integrity", requested_run_root=str(getattr(args, "run_root", "")))
    try:
        report = _verify_source_integrity()
        write_json_worm(run_dir / "reports" / "source_integrity_report.json", report, label="source_integrity_report.json")
        write_json_worm(
            run_dir / "reports" / "source_integrity_receipt.json",
            {
                "schema_id": "kt.operator.source_integrity_receipt.v1",
                "status": report["status"],
                "branch_ref": report["branch_ref"],
                "validated_head_sha": report["validated_head_sha"],
            },
            label="source_integrity_receipt.json",
        )
        if report["status"] != "PASS":
            return write_failure_artifacts(
                run_dir=run_dir,
                program_id="program.source.integrity.verify",
                failure_name="SOURCE_INTEGRITY_FAIL",
                message="; ".join(report.get("failures", [])),
                next_actions=["Repair missing or invalid governance source files and rerun source_integrity verify."],
            )
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.source.integrity.verify",
            failure_name="SOURCE_INTEGRITY_FAIL",
            message=str(exc),
            next_actions=["Inspect reports/source_integrity_report.json for the failing source path."],
        )


if __name__ == "__main__":
    raise SystemExit(main())
