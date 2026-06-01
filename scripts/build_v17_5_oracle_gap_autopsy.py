from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.v17_6_oracle_autopsy_common import build_oracle_gap_autopsy, json_safe, load_v17_5_evidence


if __name__ == "__main__":
    evidence = load_v17_5_evidence()
    gap_rows, owner_rows, posneg_rows, summary = build_oracle_gap_autopsy(evidence["rows"])
    print(
        json.dumps(
            json_safe(
                {
                    "gap_rows": len(gap_rows),
                    "owner_rows": len(owner_rows),
                    "positive_negative_rows": len(posneg_rows),
                    "summary": summary,
                }
            ),
            indent=2,
            sort_keys=True,
        )
    )
