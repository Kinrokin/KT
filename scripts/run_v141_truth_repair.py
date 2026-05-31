from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v141_truth_common import generate_all, repo_root


if __name__ == "__main__":
    print(json.dumps(generate_all(repo_root()), indent=2, sort_keys=True))
