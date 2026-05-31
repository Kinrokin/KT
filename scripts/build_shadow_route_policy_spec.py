from __future__ import annotations

import json
from pathlib import Path

from v15_oracle_harvest_common import repo_root, read_json


if __name__ == "__main__":
    path = repo_root() / "admission/shadow_route_policy_spec.json"
    print(json.dumps(read_json(path), indent=2, sort_keys=True))
