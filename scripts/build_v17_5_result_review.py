from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.v17_6_oracle_autopsy_common import build_all_outputs, json_safe


if __name__ == "__main__":
    summary = build_all_outputs()
    print(json.dumps(json_safe({"status": summary["v17_5_result_review_status"]}), indent=2, sort_keys=True))
