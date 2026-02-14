from __future__ import annotations

import subprocess
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath


def test_no_conflict_markers_in_repo() -> None:
    repo_root = bootstrap_syspath()

    # Scan tracked files only (fast, deterministic, and matches merge safety intent).
    # Using `git grep` avoids crawling large artifact directories that may exist locally.
    cmd = [
        "git",
        "grep",
        "-nE",
        r"^(<<<<<<<|=======|>>>>>>>)( |$)",
        "--",
        "KT_PROD_CLEANROOM",
        ".github",
    ]
    proc = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True)  # noqa: S603
    if proc.returncode == 1:
        return  # no matches
    if proc.returncode == 0:
        hits = (proc.stdout or "").strip()
        raise AssertionError(f"conflict markers detected:\n{hits}")
    stderr = (proc.stderr or "").strip()
    raise AssertionError(f"git grep conflict-marker scan failed (rc={proc.returncode}): {stderr}")
