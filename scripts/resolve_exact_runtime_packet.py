from __future__ import annotations

import json

from accountability_common import repo_root, read_json


if __name__ == "__main__":
    root = repo_root()
    receipt = read_json(root / "reports/v14_runtime_packet_selection_receipt.json")
    if not receipt.get("exact_name_required") or receipt.get("broad_glob_allowed"):
        raise SystemExit("exact runtime packet selection gate failed")
    print(json.dumps(receipt, indent=2, sort_keys=True))
