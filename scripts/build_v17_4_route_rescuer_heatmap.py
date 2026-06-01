from __future__ import annotations

import json

from v17_5_multirescuer_common import build_oracle_gap_outputs, json_safe, load_v17_4_evidence


if __name__ == "__main__":
    evidence = load_v17_4_evidence()
    _, _, _, heatmap = build_oracle_gap_outputs(evidence["rows"])
    print(json.dumps(json_safe(heatmap), indent=2, sort_keys=True))
