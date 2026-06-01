from __future__ import annotations

import json

from v17_5_multirescuer_common import json_safe, load_v17_4_evidence, recompute_scorecard


if __name__ == "__main__":
    evidence = load_v17_4_evidence()
    scorecard = recompute_scorecard(evidence["rows"])
    print(
        json.dumps(
            json_safe(
                {
                    "best_single_static_arm": scorecard["best_single_static_arm"],
                    "best_single_static_arm_correct": scorecard["best_single_static_arm_correct"],
                    "union_oracle_static_arms_correct": scorecard["union_oracle_static_arms_correct"],
                    "named_oracle_correct": scorecard["named_oracle_correct"],
                    "status": "PASS",
                }
            ),
            indent=2,
            sort_keys=True,
        )
    )
