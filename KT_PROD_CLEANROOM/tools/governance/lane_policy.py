from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Tuple


_TRUTHY = {"1", "true", "yes", "on"}


def is_truthy_env(name: str) -> bool:
    return str(os.environ.get(name, "")).strip().lower() in _TRUTHY


def canonical_lane_enabled() -> bool:
    return is_truthy_env("KT_CANONICAL_LANE")


def repo_clean_gate_for_current_lane(repo_root: Path) -> Tuple[bool, str]:
    if not canonical_lane_enabled():
        return True, ""
    try:
        out = subprocess.check_output(["git", "status", "--porcelain"], cwd=str(repo_root), text=True)
    except Exception as exc:  # noqa: BLE001
        return False, f"FAIL_CLOSED: unable to run git status: {exc}"
    if out.strip():
        return False, "FAIL_CLOSED: repo is not clean"
    return True, ""
