from __future__ import annotations

import json

from accountability_common import repo_root, read_json
from v14_omni_common import build_routing_and_isolation


if __name__ == "__main__":
    root = repo_root()
    build_routing_and_isolation(root)
    print(json.dumps(read_json(root / "reports/structure_bound_routing_plan_receipt.json"), indent=2, sort_keys=True))
