from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v15_oracle_harvest_common import repo_root, write_all


if __name__ == "__main__":
    print(json.dumps(write_all(repo_root()), indent=2, sort_keys=True))
