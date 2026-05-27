from __future__ import annotations

import json

from accountability_common import repo_root, read_json
from v14_omni_common import build_governance_cross_domain_commercial


if __name__ == "__main__":
    root = repo_root()
    build_governance_cross_domain_commercial(root)
    print(json.dumps(read_json(root / "reports/v14_accountability_inheritance_receipt.json"), indent=2, sort_keys=True))
