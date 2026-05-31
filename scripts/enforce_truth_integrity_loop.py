from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v141_truth_common import read_json, repo_root, truth_integrity_receipt


if __name__ == "__main__":
    root = repo_root()
    path = root / "reports/v14_truth_integrity_audit_receipt.json"
    receipt = read_json(path) if path.exists() else truth_integrity_receipt()
    print(json.dumps(receipt, indent=2, sort_keys=True))
    raise SystemExit(0 if receipt["release_authority"] == "BLOCK_STRONG_CLAIMS" else 1)
