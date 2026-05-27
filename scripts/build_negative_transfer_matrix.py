from __future__ import annotations

import json

from accountability_common import repo_root, read_json
from v14_omni_common import build_oracle_and_capability


if __name__ == "__main__":
    root = repo_root()
    build_oracle_and_capability(root)
    print(json.dumps(read_json(root / "capability/negative_transfer_matrix.json"), indent=2, sort_keys=True))
