from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import repo_root, utc_now_iso_z


def _git(*, root: Path, args: Sequence[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=str(root), text=True).strip()


def _env(*, root: Path) -> Dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src") + os.pathsep + str(root / "KT_PROD_CLEANROOM")
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    return env


def _run(*, root: Path, cmd: Sequence[str], env: Dict[str, str]) -> Tuple[int, str]:
    proc = subprocess.run(list(cmd), cwd=str(root), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return int(proc.returncode), proc.stdout or ""


def _record(
    *,
    out: List[Dict[str, Any]],
    check_id: str,
    scope: str,
    critical: bool,
    dirty_sensitive: bool,
    command: str,
    rc: int,
    output: str,
    summary: str,
) -> None:
    row: Dict[str, Any] = {
        "check_id": check_id,
        "scope": scope,
        "critical": bool(critical),
        "dirty_sensitive": bool(dirty_sensitive),
        "status": "PASS" if rc == 0 else "FAIL",
        "summary": summary,
        "command": command,
        "observed": output.strip().splitlines()[-1] if output.strip() else "",
    }
    if rc != 0:
        row["output_tail"] = output.strip().splitlines()[-20:]
    out.append(row)


def _clean_clone_operator_smoke(*, root: Path) -> Dict[str, Any]:
    tmp_dir = Path(tempfile.mkdtemp(prefix="kt_truth_matrix_clone_"))
    try:
        clone_dir = tmp_dir / "repo"
        subprocess.check_call(["git", "clone", str(root), str(clone_dir)], cwd=str(tmp_dir))
        env = _env(root=clone_dir)
        head = _git(root=clone_dir, args=["rev-parse", "HEAD"])
        rc, out = _run(
            root=clone_dir,
            cmd=[
                "python",
                "-m",
                "pytest",
                "-q",
                "KT_PROD_CLEANROOM/tests/fl3/test_hat_demo_guardrails.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_operator_cli.py",
            ],
            env=env,
        )
        return {"rc": rc, "output": out, "head_sha": head}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def build_live_validation_index(*, root: Path, skip_clean_clone: bool) -> Dict[str, Any]:
    env = _env(root=root)
    checks: List[Dict[str, Any]] = []
    constitution_report = str((Path(tempfile.gettempdir()) / "kt_constitution_guard_report.md").resolve())

    commands = [
        (
            "constitutional_guard",
            "canonical_runtime",
            True,
            False,
            ["python", "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tools/check_constitution.py", "--report", constitution_report],
            "constitutional guard passes with canonical runtime scope enforced",
        ),
        (
            "runtime_suite",
            "canonical_runtime",
            True,
            False,
            ["python", "-m", "pytest", "-q", "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests"],
            "runtime suite passed",
        ),
        (
            "critical_governance_regression_suite",
            "core_truth_repair",
            True,
            False,
            [
                "python",
                "-m",
                "pytest",
                "-q",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_invariants_gate.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_no_network_dry_run.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_fl3_meta_evaluator.py",
                "KT_PROD_CLEANROOM/tools/verification/tests/test_reconcile_and_schemas.py",
            ],
            "critical regression suite passed",
        ),
        (
            "lane_policy_repair_suite",
            "governance_lanes",
            True,
            False,
            [
                "python",
                "-m",
                "pytest",
                "-q",
                "KT_PROD_CLEANROOM/tests/fl3/test_epic16_admission_gates.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_epic15_tournament_runner.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_epic15_merge_evaluator.py",
            ],
            "lane-aware governance gate suite passed",
        ),
        (
            "law_bundle_integrity",
            "law_surface",
            True,
            False,
            [
                "python",
                "-m",
                "pytest",
                "-q",
                "KT_PROD_CLEANROOM/tests/fl3/test_fl3_law_bundle_integrity.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_fl3_meta_evaluator.py",
            ],
            "law bundle integrity suite passed",
        ),
        (
            "trust_zone_validator",
            "boundary_purification",
            True,
            False,
            ["python", "-m", "tools.operator.trust_zone_validate"],
            "trust-zone validator passed",
        ),
        (
            "current_worktree_cleanroom_suite",
            "active_repo_validation",
            True,
            True,
            ["python", "-m", "pytest", "-q", "KT_PROD_CLEANROOM/tests", "-q", "-ra", "--maxfail=100"],
            "current-worktree cleanroom suite passed",
        ),
    ]

    for check_id, scope, critical, dirty_sensitive, cmd, success_summary in commands:
        rc, out = _run(root=root, cmd=cmd, env=env)
        _record(
            out=checks,
            check_id=check_id,
            scope=scope,
            critical=critical,
            dirty_sensitive=dirty_sensitive,
            command=" ".join(cmd),
            rc=rc,
            output=out,
            summary=success_summary if rc == 0 else success_summary.replace("passed", "failed"),
        )

    if skip_clean_clone:
        checks.append(
            {
                "check_id": "operator_clean_clone_smoke",
                "scope": "clean_clone_validation",
                "critical": True,
                "dirty_sensitive": False,
                "status": "SKIP",
                "summary": "operator clean-clone smoke skipped by request",
                "command": "git clone <repo> <tmp> && python -m pytest -q KT_PROD_CLEANROOM/tests/fl3/test_hat_demo_guardrails.py KT_PROD_CLEANROOM/tests/fl3/test_operator_cli.py",
            }
        )
    else:
        clean_clone = _clean_clone_operator_smoke(root=root)
        checks.append(
            {
                "check_id": "operator_clean_clone_smoke",
                "scope": "clean_clone_validation",
                "critical": True,
                "dirty_sensitive": False,
                "status": "PASS" if int(clean_clone["rc"]) == 0 else "FAIL",
                "summary": "operator clean-clone smoke passed" if int(clean_clone["rc"]) == 0 else "operator clean-clone smoke failed",
                "command": "git clone <repo> <tmp> && python -m pytest -q KT_PROD_CLEANROOM/tests/fl3/test_hat_demo_guardrails.py KT_PROD_CLEANROOM/tests/fl3/test_operator_cli.py",
                "observed": str(clean_clone["output"]).strip().splitlines()[-1] if str(clean_clone["output"]).strip() else "",
                "context": {"clean_clone_head_sha": str(clean_clone["head_sha"]).strip()},
            }
        )

    dirty_lines = subprocess.check_output(["git", "status", "--short"], cwd=str(root), text=True).splitlines()
    return {
        "schema_id": "kt.operator.live_validation_index.v1",
        "generated_utc": utc_now_iso_z(),
        "branch_ref": _git(root=root, args=["rev-parse", "--abbrev-ref", "HEAD"]),
        "worktree": {
            "git_dirty": bool(dirty_lines),
            "head_sha": _git(root=root, args=["rev-parse", "HEAD"]),
            "dirty_files": [line.strip() for line in dirty_lines if line.strip()],
        },
        "checks": checks,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Run the canonical truth matrix and write a live validation index.")
    ap.add_argument("--out", default="KT_PROD_CLEANROOM/reports/live_validation_index.json")
    ap.add_argument("--skip-clean-clone", action="store_true")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    out_path = Path(str(args.out)).expanduser()
    if not out_path.is_absolute():
        out_path = (root / out_path).resolve()
    index = build_live_validation_index(root=root, skip_clean_clone=bool(args.skip_clean_clone))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(index, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")
    critical_fails = [
        row
        for row in index.get("checks", [])
        if isinstance(row, dict) and bool(row.get("critical")) and str(row.get("status", "")).strip().upper() == "FAIL"
    ]
    print(json.dumps({"critical_failures": len(critical_fails), "head_sha": index["worktree"]["head_sha"]}, sort_keys=True, ensure_ascii=True))
    return 0 if not critical_fails else 2


if __name__ == "__main__":
    raise SystemExit(main())
