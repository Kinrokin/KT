from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_final_summary_serialization_smoke_script_executes():
    result = subprocess.run(
        [sys.executable, "scripts/smoke_test_v17_1_final_summary_serialization.py"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert "final/final_summary.json" in result.stdout
