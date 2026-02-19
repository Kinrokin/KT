from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    # .../KT_PROD_CLEANROOM/tests/fl3/test_operator_cli.py -> repo root
    return here.parents[3]


def _operator_test_root(repo_root: Path) -> Path:
    return (repo_root / "KT_PROD_CLEANROOM" / "exports" / "_runs" / "_TEST_OPERATOR").resolve()


def _base_env(repo_root: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src") + os.pathsep + str(
        repo_root / "KT_PROD_CLEANROOM"
    )
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    return env


def test_kt_cli_status_smoke_and_worm_collision() -> None:
    repo_root = _repo_root()
    out_root = _operator_test_root(repo_root)
    out_root.mkdir(parents=True, exist_ok=True)
    run_root = out_root / "status_smoke"
    if run_root.exists():
        # Best-effort cleanup of prior test run (untracked under exports/_runs).
        for p in sorted(run_root.rglob("*"), reverse=True):
            if p.is_file():
                p.unlink()
            elif p.is_dir():
                try:
                    p.rmdir()
                except OSError:
                    pass
        try:
            run_root.rmdir()
        except OSError:
            pass

    env = _base_env(repo_root)
    cmd = ["python", "-m", "tools.operator.kt_cli", "--run-root", str(run_root), "status"]
    p1 = subprocess.run(cmd, cwd=str(repo_root), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert p1.returncode == 0, p1.stdout
    assert (run_root / "verdict.txt").exists()
    verdict = (run_root / "verdict.txt").read_text(encoding="utf-8", errors="replace")
    assert "KT_STATUS_PASS" in verdict

    # Second run into same run_root must fail-closed (WORM collision).
    p2 = subprocess.run(cmd, cwd=str(repo_root), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert p2.returncode != 0
    assert "FAIL_CLOSED" in (p2.stdout or "")

    # CLI must not mutate repo-tracked state.
    st = subprocess.check_output(["git", "status", "--porcelain=v1"], cwd=str(repo_root), text=True)
    assert st.strip() == ""

