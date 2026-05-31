from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v141_truth_common import emergency_repair_receipt, read_json, repo_root


if __name__ == "__main__":
    root = repo_root()
    path = root / "reports/v14_emergency_repair_subprotocol_receipt.json"
    print(json.dumps(read_json(path) if path.exists() else emergency_repair_receipt(), indent=2, sort_keys=True))
