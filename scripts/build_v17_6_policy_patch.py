from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.v17_6_oracle_autopsy_common import (
    build_oracle_gap_autopsy,
    build_policy_patch,
    json_safe,
    load_v17_5_evidence,
    nonselected_diagnosis,
    recompute_scorecard,
    route_regret_overdominance,
)


if __name__ == "__main__":
    evidence = load_v17_5_evidence()
    scorecard = recompute_scorecard(evidence["rows"])
    _, _, _, gap_summary = build_oracle_gap_autopsy(evidence["rows"])
    policy, thresholds, runtime_features, base_policy = build_policy_patch(
        scorecard,
        route_regret_overdominance(evidence["rows"]),
        nonselected_diagnosis(evidence["rows"], "base_kt_hat_compact"),
        nonselected_diagnosis(evidence["rows"], "math_act_adapter_global"),
        gap_summary,
    )
    print(
        json.dumps(
            json_safe(
                {
                    "policy": policy,
                    "thresholds": thresholds,
                    "runtime_features": runtime_features,
                    "base_policy": base_policy,
                }
            ),
            indent=2,
            sort_keys=True,
        )
    )
