from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v141_truth_common import isolation_reconciliation_receipt, read_json, repo_root


if __name__ == "__main__":
    root = repo_root()
    path = root / "reports/v14_isolation_receipt_reconciliation.json"
    print(json.dumps(read_json(path) if path.exists() else isolation_reconciliation_receipt(), indent=2, sort_keys=True))
