from __future__ import annotations

import os
import subprocess
from pathlib import Path

from tools.verification.seal_mode_test_roots import group_root, unique_run_dir


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    return here.parents[3]


def _base_env(repo_root: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src") + os.pathsep + str(
        repo_root / "KT_PROD_CLEANROOM"
    )
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    return env


def _git_status(repo_root: Path) -> str:
    return subprocess.check_output(["git", "status", "--porcelain=v1"], cwd=str(repo_root), text=True)


def test_kt_cli_refuses_run_root_outside_exports_runs(tmp_path: Path) -> None:
    repo_root = _repo_root()
    env = _base_env(repo_root)

    bad_root = tmp_path / "bad_run_root_outside_exports"
    p = subprocess.run(
        ["python", "-m", "tools.operator.kt_cli", "--run-root", str(bad_root), "hat-demo"],
        cwd=str(repo_root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert p.returncode != 0
    assert "FAIL_CLOSED" in (p.stdout or "")


def test_kt_cli_hat_demo_smoke_and_report_render(tmp_path: Path) -> None:
    repo_root = _repo_root()
    env = _base_env(repo_root)
    baseline_status = _git_status(repo_root)

    out_root = group_root(repo_root=repo_root, group="OPERATOR")
    out_root.mkdir(parents=True, exist_ok=True)

    hat_run = unique_run_dir(parent=out_root, label="hat_demo_smoke")
    report_run = unique_run_dir(parent=out_root, label="hat_demo_report_smoke")

    hat_cmd = ["python", "-m", "tools.operator.kt_cli", "--run-root", str(hat_run), "hat-demo"]
    report_cmd = ["python", "-m", "tools.operator.kt_cli", "--run-root", str(report_run), "report", "--run", str(hat_run)]
    if baseline_status.strip():
        hat_cmd.append("--allow-dirty")
        report_cmd.append("--allow-dirty")

    p1 = subprocess.run(
        hat_cmd,
        cwd=str(repo_root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert p1.returncode == 0, p1.stdout
    assert (hat_run / "verdict.txt").exists()
    assert (hat_run / "hat_demo" / "router_run_report.json").exists()

    p2 = subprocess.run(
        report_cmd,
        cwd=str(repo_root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert p2.returncode == 0, p2.stdout
    assert (report_run / "report_render.txt").exists()
    txt = (report_run / "report_render.txt").read_text(encoding="utf-8", errors="replace")
    assert "hat_demo_router_run_report" in txt

    assert _git_status(repo_root) == baseline_status
