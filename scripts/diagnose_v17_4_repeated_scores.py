from __future__ import annotations

import json

from v17_5_multirescuer_common import build_repeated_score_diagnosis, json_safe, load_v17_4_evidence


if __name__ == "__main__":
    evidence = load_v17_4_evidence()
    print(json.dumps(json_safe(build_repeated_score_diagnosis(evidence["rows"], evidence["scorecard"])), indent=2, sort_keys=True))
