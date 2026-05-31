from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v141_truth_common import adapter_identity_receipt, read_json, repo_root


if __name__ == "__main__":
    root = repo_root()
    path = root / "reports/v14_adapter_identity_adjudication_receipt.json"
    receipt = read_json(path) if path.exists() else adapter_identity_receipt()
    print(json.dumps(receipt, indent=2, sort_keys=True))
    raise SystemExit(0)
