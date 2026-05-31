from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_v16_functional_implementation_gate_runs_real_scripts(tmp_path):
    out = tmp_path / "functional_receipt.json"
    proc = subprocess.run(
        [sys.executable, "scripts/validate_v16_functional_implementation.py", "--out", str(out)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    receipt = json.loads(out.read_text(encoding="utf-8"))
    assert receipt["gate_pass"] is True
    assert all(item["has_main"] for item in receipt["script_status"])
    assert all(item["non_placeholder"] for item in receipt["test_status"])
