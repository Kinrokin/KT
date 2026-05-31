from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_shadow_replay_improves_over_v15_feature_bound_without_authority():
    subprocess.run([sys.executable, "scripts/build_v16_shadow_route_policy.py"], cwd=ROOT, check=True)
    proc = subprocess.run([sys.executable, "scripts/replay_v16_shadow_policy.py"], cwd=ROOT, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    scorecard = json.loads((ROOT / "reports/v16_shadow_replay_scorecard.json").read_text(encoding="utf-8"))
    assert scorecard["shadow_policy_correct"] > scorecard["feature_bound_correct"]
    assert scorecard["oracle_conversion_rate"] > scorecard["baseline_oracle_conversion_rate"]
    assert scorecard["runtime_authority"] is False
    assert scorecard["promotion_authority"] is False
