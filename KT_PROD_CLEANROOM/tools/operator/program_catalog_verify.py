from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, make_run_dir, repo_root, utc_now_iso_z, write_failure_artifacts, write_json_worm


def _catalog_path(root: Path) -> Path:
    return (root / "KT_PROD_CLEANROOM" / "governance" / "program_catalog.json").resolve()


def _resolve(root: Path, rel: str) -> Path:
    return (root / rel).resolve()


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=str(root), text=True).strip()


def _verify_catalog(*, check_job: str = "", strict: bool = False) -> Dict[str, Any]:
    root = repo_root()
    catalog = load_json(_catalog_path(root))
    failures: List[str] = []
    programs_report: List[Dict[str, Any]] = []
    jobs_report: List[Dict[str, Any]] = []

    for row in catalog.get("programs", []):
        if not isinstance(row, dict):
            continue
        program_id = str(row.get("program_id", "")).strip()
        impl = str(row.get("implementation_path", "")).strip()
        status = "PASS"
        if not program_id or not impl or not _resolve(root, impl).exists():
            status = "FAIL"
            failures.append(f"program:{program_id or '<missing>'}")
        programs_report.append({"implementation_path": impl, "program_id": program_id, "status": status})

    for row in catalog.get("ci_jobs", []):
        if not isinstance(row, dict):
            continue
        job_id = str(row.get("job_id", "")).strip()
        yaml_path = str(row.get("yaml_path", "")).strip()
        if check_job and job_id != check_job:
            continue
        status = "PASS"
        if not job_id or not yaml_path or not _resolve(root, yaml_path).exists():
            status = "FAIL"
            failures.append(f"job:{job_id or '<missing>'}")
        jobs_report.append({"job_id": job_id, "status": status, "yaml_path": yaml_path})

    if check_job and not jobs_report:
        failures.append(f"job:{check_job}:missing")
    report = {
        "checked_job": check_job or None,
        "failures": failures,
        "generated_utc": utc_now_iso_z(),
        "branch_ref": _git(root, "rev-parse", "--abbrev-ref", "HEAD"),
        "validated_head_sha": _git(root, "rev-parse", "HEAD"),
        "programs": programs_report,
        "schema_id": "kt.operator.program_catalog_report.v1",
        "status": "PASS" if not failures else "FAIL",
        "strict": bool(strict),
        "yaml_jobs": jobs_report,
    }
    return report


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Verify KT Titanium program catalog.")
    ap.add_argument("--run-root", default="")
    ap.add_argument("--check-job", default="")
    ap.add_argument("--strict", action="store_true")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    run_dir = make_run_dir(cmd_name="program-catalog-verify", requested_run_root=str(args.run_root))
    try:
        report = _verify_catalog(check_job=str(args.check_job), strict=bool(args.strict))
        write_json_worm(run_dir / "reports" / "program_catalog_report.json", report, label="program_catalog_report.json")
        if report["status"] != "PASS":
            return write_failure_artifacts(
                run_dir=run_dir,
                program_id="program.catalog.verify",
                failure_name="CATALOG_INCOMPLETE",
                message="; ".join(report.get("failures", [])),
                next_actions=["Add the missing program implementation or CI YAML path and rerun program_catalog_verify."],
            )
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.catalog.verify",
            failure_name="CATALOG_INCOMPLETE",
            message=str(exc),
            next_actions=["Inspect KT_PROD_CLEANROOM/governance/program_catalog.json and referenced paths."],
        )


if __name__ == "__main__":
    raise SystemExit(main())
