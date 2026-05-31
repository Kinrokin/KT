from __future__ import annotations

import json
from pathlib import Path

from v15_oracle_harvest_common import repo_root, read_json


if __name__ == "__main__":
    receipt = read_json(repo_root() / "reports/oracle_leakage_scan_receipt.json")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    raise SystemExit(0 if receipt["status"] == "PASS" else 1)
