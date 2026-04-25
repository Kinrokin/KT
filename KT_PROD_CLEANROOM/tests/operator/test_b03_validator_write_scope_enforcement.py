from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


VALIDATOR_REFS = [
    "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/e1_bounded_campaign_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/final_current_head_adjudication_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/w3_externality_and_comparative_proof_validate.py",
]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _clone_with_t4_overlay(tmp_path: Path) -> Path:
    root = _repo_root()
    clone_root = tmp_path / "repo_clone"
    proc = subprocess.run(
        ["git", "clone", "--quiet", str(root), str(clone_root)],
        cwd=str(root.parent),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout
    for rel in VALIDATOR_REFS:
        source = root / rel
        target = clone_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    return clone_root


def _env(root: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    return env


def _run(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", *args],
        cwd=str(root),
        env=_env(root),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def _git_status_lines(root: Path) -> list[str]:
    proc = subprocess.run(
        ["git", "status", "--short"],
        cwd=str(root),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def test_validator_family_default_runs_stay_in_declared_scope(tmp_path: Path) -> None:
    clone_root = _clone_with_t4_overlay(tmp_path)
    baseline_dirty = _git_status_lines(clone_root)

    for module_name in (
        "tools.operator.e1_bounded_campaign_validate",
        "tools.operator.final_current_head_adjudication_validate",
        "tools.operator.w3_externality_and_comparative_proof_validate",
    ):
        proc = _run(clone_root, module_name)
        assert proc.returncode == 0, proc.stdout
        assert _git_status_lines(clone_root) == baseline_dirty, proc.stdout

    proc = _run(clone_root, "tools.operator.benchmark_constitution_validate")
    assert proc.returncode == 0, proc.stdout

    receipt_path = clone_root / "KT_PROD_CLEANROOM" / "reports" / "validator_write_scope_enforcement_receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["tranche_id"] == "B03_T4_VALIDATOR_WRITE_SCOPE_ENFORCEMENT"
    assert receipt["unexpected_postwrite_paths"] == []
    assert receipt["undeclared_created_paths"] == []

    dirty_lines = _git_status_lines(clone_root)
    assert dirty_lines
    added_dirty = [line for line in dirty_lines if line not in baseline_dirty]
    assert added_dirty
    assert all("KT_PROD_CLEANROOM/reports/validator_write_scope_enforcement_receipt.json" in line for line in added_dirty)


def test_benchmark_validator_fails_closed_on_out_of_scope_tracked_output(tmp_path: Path) -> None:
    clone_root = _clone_with_t4_overlay(tmp_path)

    proc = _run(
        clone_root,
        "tools.operator.benchmark_constitution_validate",
        "--write-scope-receipt-output",
        "KT_PROD_CLEANROOM/reports/final_current_head_adjudication_receipt.json",
    )

    assert proc.returncode != 0
    assert "FAIL_CLOSED: tracked output outside allowed scope" in proc.stdout
