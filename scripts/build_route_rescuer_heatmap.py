from __future__ import annotations

import json

from v15_oracle_harvest_common import repo_root, read_json


if __name__ == "__main__":
    print(json.dumps(read_json(repo_root() / "reports/route_rescuer_heatmap.json"), indent=2, sort_keys=True))
