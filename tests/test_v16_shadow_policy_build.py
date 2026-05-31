from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_shadow_policy_build_emits_shadow_only_policy():
    proc = subprocess.run([sys.executable, "scripts/build_v16_shadow_route_policy.py"], cwd=ROOT, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    policy = json.loads((ROOT / "admission/v16_shadow_route_policy.json").read_text(encoding="utf-8"))
    assert policy["runtime_authority"] is False
    assert policy["promotion_authority"] is False
    assert policy["adapter_training_authorized"] is False
    assert policy["oracle_correctness_used_as_input_feature"] is False
    assert policy["selection_rules"]
    assert "oracle_correct" not in policy["allowed_runtime_features"]
