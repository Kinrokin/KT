from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    stale = json.loads((ROOT / "reports/repo_stale_head_reference_index_v1.json").read_text(encoding="utf-8"))
    if stale.get("current_truth_stale_ref_file_count", 0) > 0:
        raise SystemExit("stale head refs found in current truth surfaces")
    print(json.dumps({"schema_id": "kt.stale_head_ref_check.v1", "status": "PASS", "review_rows": len(stale.get("rows", []))}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
