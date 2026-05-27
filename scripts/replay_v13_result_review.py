from __future__ import annotations

import json

from accountability_common import repo_root, read_json
from v14_omni_common import reconcile_v13_scores


if __name__ == "__main__":
    root = repo_root()
    reconcile_v13_scores(root)
    print(json.dumps(read_json(root / "reports/v13_result_review_receipt.json"), indent=2, sort_keys=True))
