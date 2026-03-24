from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _cleanroom_root() -> Path:
    return Path(__file__).resolve().parents[3]


def main(argv: list[str] | None = None) -> int:
    cleanroom_root = _cleanroom_root()
    args = list(sys.argv[1:] if argv is None else argv)
    command = [sys.executable, "-m", "tools.operator.omega_gate", *args]
    return subprocess.call(command, cwd=str(cleanroom_root))
