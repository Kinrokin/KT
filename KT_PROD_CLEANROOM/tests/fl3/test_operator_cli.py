from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from tools.verification.seal_mode_test_roots import group_root, unique_run_dir


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    # .../KT_PROD_CLEANROOM/tests/fl3/test_operator_cli.py -> repo root
    return here.parents[3]


def _operator_test_root(repo_root: Path) -> Path:
    return group_root(repo_root=repo_root, group="OPERATOR")


def _base_env(repo_root: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src") + os.pathsep + str(
        repo_root / "KT_PROD_CLEANROOM"
    )
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    return env


def test_kt_cli_status_smoke_without_external_pythonpath() -> None:
    repo_root = _repo_root()
    cleanroom_root = repo_root / "KT_PROD_CLEANROOM"
    out_root = _operator_test_root(repo_root)
    out_root.mkdir(parents=True, exist_ok=True)
    run_root = unique_run_dir(parent=out_root, label="status_smoke_no_pythonpath")

    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")

    cmd = ["python", "-m", "tools.operator.kt_cli", "--run-root", str(run_root), "status", "--allow-dirty"]
    p = subprocess.run(
        cmd,
        cwd=str(cleanroom_root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert p.returncode == 0, p.stdout
    assert (run_root / "verdict.txt").exists()
    verdict = (run_root / "verdict.txt").read_text(encoding="utf-8", errors="replace")
    assert "KT_STATUS_PASS" in verdict


def test_kt_cli_status_smoke_and_worm_collision() -> None:
    repo_root = _repo_root()
    out_root = _operator_test_root(repo_root)
    out_root.mkdir(parents=True, exist_ok=True)
    run_root = unique_run_dir(parent=out_root, label="status_smoke")

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


@pytest.mark.skipif(
    os.environ.get("KT_SEAL_MODE") == "1",
    reason="Writes to repo root to force git-dirty state; incompatible with seal-mode IO guard and preflight clean repo rule.",
)
def test_kt_cli_allow_dirty_gate() -> None:
    repo_root = _repo_root()
    marker = repo_root / "__kt_dirty_marker.tmp"
    if marker.exists():
        marker.unlink()

    out_root = _operator_test_root(repo_root)
    out_root.mkdir(parents=True, exist_ok=True)
    run_root_fail = unique_run_dir(parent=out_root, label="dirty_gate_fail")
    run_root_pass = unique_run_dir(parent=out_root, label="dirty_gate_pass")

    env = _base_env(repo_root)
    try:
        marker.write_text("dirty\n", encoding="utf-8")

        # Default must FAIL_CLOSED on dirty worktree.
        cmd_fail = ["python", "-m", "tools.operator.kt_cli", "--run-root", str(run_root_fail), "status"]
        p1 = subprocess.run(cmd_fail, cwd=str(repo_root), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        assert p1.returncode != 0
        assert "FAIL_CLOSED" in (p1.stdout or "")
        assert (run_root_fail / "verdict.txt").exists()

        # Explicit allow should PASS even with dirty worktree.
        cmd_pass = ["python", "-m", "tools.operator.kt_cli", "--run-root", str(run_root_pass), "status", "--allow-dirty"]
        p2 = subprocess.run(cmd_pass, cwd=str(repo_root), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        assert p2.returncode == 0, p2.stdout
        assert (run_root_pass / "verdict.txt").exists()

    finally:
        if marker.exists():
            marker.unlink()

    # Repo must be clean after cleanup.
    st = subprocess.check_output(["git", "status", "--porcelain=v1"], cwd=str(repo_root), text=True)
    assert st.strip() == ""


def test_operator_wrapper_script_exists() -> None:
    repo_root = _repo_root()
    p = repo_root / "KT_PROD_CLEANROOM" / "tools" / "operator" / "kt.ps1"
    assert p.is_file()
    txt = p.read_text(encoding="utf-8", errors="replace")
    assert "python -m tools.operator.kt_cli" in txt
