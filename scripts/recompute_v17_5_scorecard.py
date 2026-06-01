from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.v17_6_oracle_autopsy_common import json_safe, load_v17_5_evidence, recompute_scorecard


if __name__ == "__main__":
    evidence = load_v17_5_evidence()
    print(json.dumps(json_safe(recompute_scorecard(evidence["rows"])), indent=2, sort_keys=True))
