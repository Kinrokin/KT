from __future__ import annotations

import json

from accountability_common import repo_root, read_json
from v14_omni_common import build_claim_and_boundary_artifacts


if __name__ == "__main__":
    root = repo_root()
    build_claim_and_boundary_artifacts(root)
    print(json.dumps(read_json(root / "reports/v14_claim_admissibility_casefile.json"), indent=2, sort_keys=True))
