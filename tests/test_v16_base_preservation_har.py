from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_v16_base_preservation_and_harmful_activation_thresholds():
    subprocess.run([sys.executable, "scripts/run_v16_crossroad_shadow.py"], cwd=ROOT, check=True)
    bpr = json.loads((ROOT / "reports/v16_base_preservation_receipt.json").read_text(encoding="utf-8"))
    har = json.loads((ROOT / "reports/v16_harmful_activation_receipt.json").read_text(encoding="utf-8"))
    assert bpr["base_preservation_rate"] >= 0.95
    assert bpr["status"] == "PASS"
    assert har["harmful_activation_rate"] <= 0.10
    assert har["status"] == "PASS"
