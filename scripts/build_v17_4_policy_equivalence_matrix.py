from __future__ import annotations

import json

from v17_5_multirescuer_common import build_repeated_score_diagnosis, json_safe, load_v17_4_evidence


if __name__ == "__main__":
    evidence = load_v17_4_evidence()
    receipt = build_repeated_score_diagnosis(evidence["rows"], evidence["scorecard"])
    print(json.dumps(json_safe(receipt["jaccard_overlap_by_policy_pair"]), indent=2, sort_keys=True))
