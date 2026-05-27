from __future__ import annotations

import json

from accountability_common import repo_root, read_json
from v14_omni_common import build_specialist_admission


if __name__ == "__main__":
    root = repo_root()
    build_specialist_admission(root)
    print(json.dumps(read_json(root / "reports/specialist_admission_atlas_receipt.json"), indent=2, sort_keys=True))
