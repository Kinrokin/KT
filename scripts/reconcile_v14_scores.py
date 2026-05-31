from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v141_truth_common import read_json, repo_root, score_reconciliation


if __name__ == "__main__":
    root = repo_root()
    path = root / "reports/v14_score_reconciliation_receipt.json"
    receipt = read_json(path) if path.exists() else score_reconciliation()
    print(json.dumps(receipt, indent=2, sort_keys=True))
    raise SystemExit(0 if receipt["status"] == "PASS_RECONCILED" else 1)
