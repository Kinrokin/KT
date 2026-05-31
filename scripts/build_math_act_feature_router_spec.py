from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v141_truth_common import MATH_ACT_POLICY, read_json, repo_root


if __name__ == "__main__":
    root = repo_root()
    path = root / "admission/math_act_feature_router_policy.json"
    print(json.dumps(read_json(path) if path.exists() else MATH_ACT_POLICY, indent=2, sort_keys=True))
