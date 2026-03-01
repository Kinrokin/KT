from __future__ import annotations

import os
import re
import time
from pathlib import Path


def is_seal_mode() -> bool:
    return os.environ.get("KT_SEAL_MODE") == "1"


def write_root(*, repo_root: Path) -> Path:
    if is_seal_mode():
        return (repo_root / "KT_PROD_CLEANROOM" / "exports" / "adapters_shadow" / "_tmp" / "tests").resolve()
    return (repo_root / "KT_PROD_CLEANROOM" / "exports" / "_runs").resolve()


def group_root(*, repo_root: Path, group: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9]+", "_", str(group).strip()).strip("_").upper() or "TEST"
    return (write_root(repo_root=repo_root) / f"_TEST_{safe}").resolve()


def unique_run_dir(*, parent: Path, label: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", str(label).strip()).strip("_") or "run"
    return (parent / f"{safe}_{os.getpid()}_{time.time_ns()}").resolve()
