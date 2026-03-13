from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict

from tools.operator.truth_authority import load_json_ref


def _git(cwd: Path, *args: str) -> None:
    subprocess.check_call(["git", *args], cwd=str(cwd))


def _git_commit_all(cwd: Path, msg: str) -> None:
    _git(cwd, "add", "-A")
    subprocess.check_call(["git", "-c", "commit.gpgsign=false", "commit", "-m", msg], cwd=str(cwd))


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_load_json_ref_falls_back_to_remote_tracking_branch_when_local_branch_missing(tmp_path: Path) -> None:
    # Reproduce the real external-admissibility case:
    # - A fresh clone has origin/kt_truth_ledger but no local kt_truth_ledger branch.
    # - The resolver contract uses "kt_truth_ledger:<path>" refs.
    origin = tmp_path / "origin.git"
    subprocess.check_call(["git", "init", "--bare", str(origin)])

    seed = tmp_path / "seed"
    subprocess.check_call(["git", "init", "-b", "main", str(seed)])
    _git(seed, "config", "user.email", "kt-test@example.invalid")
    _git(seed, "config", "user.name", "KT Test")

    (seed / "README.md").write_text("seed\n", encoding="utf-8")
    _git_commit_all(seed, "seed main")
    _git(seed, "remote", "add", "origin", str(origin))
    _git(seed, "push", "-u", "origin", "main")

    _git(seed, "checkout", "-b", "kt_truth_ledger")
    _write_json(
        seed / "ledger" / "current" / "current_pointer.json",
        {"schema_id": "test.pointer.v1", "truth_subject_commit": "abc1234"},
    )
    _git_commit_all(seed, "seed ledger pointer")
    _git(seed, "push", "-u", "origin", "kt_truth_ledger")

    clone = tmp_path / "clone"
    subprocess.check_call(["git", "clone", str(origin), str(clone)])

    # Confirm: no local kt_truth_ledger branch exists in the clone.
    proc = subprocess.run(
        ["git", "show-ref", "--verify", "--quiet", "refs/heads/kt_truth_ledger"],
        cwd=str(clone),
    )
    assert proc.returncode != 0

    payload = load_json_ref(root=clone, ref="kt_truth_ledger:ledger/current/current_pointer.json")
    assert payload["truth_subject_commit"] == "abc1234"

