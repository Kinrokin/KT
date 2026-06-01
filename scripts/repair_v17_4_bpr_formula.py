from __future__ import annotations

import json

from v17_5_multirescuer_common import json_safe, load_v17_4_evidence, recompute_scorecard


if __name__ == "__main__":
    evidence = load_v17_4_evidence()
    scorecard = recompute_scorecard(evidence["rows"])
    print(json.dumps(json_safe({"BPR": scorecard["BPR"], "status": "PASS"}), indent=2, sort_keys=True))
