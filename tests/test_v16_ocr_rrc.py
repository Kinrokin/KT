from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_v16_ocr_and_route_regret_closure_scorecards_pass():
    subprocess.run([sys.executable, "scripts/run_v16_crossroad_shadow.py"], cwd=ROOT, check=True)
    ocr = json.loads((ROOT / "reports/v16_oracle_conversion_rate_scorecard.json").read_text(encoding="utf-8"))
    rrc = json.loads((ROOT / "reports/v16_route_regret_closure_scorecard.json").read_text(encoding="utf-8"))
    assert ocr["oracle_conversion_rate"] > ocr["baseline_ocr"]
    assert ocr["status"] == "PASS"
    assert rrc["route_regret_closure"] >= 0.30
    assert rrc["status"] == "PASS"
