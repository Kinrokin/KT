from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v141_truth_common import V15_SPEC, read_json, repo_root


if __name__ == "__main__":
    root = repo_root()
    path = root / "packets/ktg3full_v15_truth_route/PACKET_MANIFEST.json"
    print(json.dumps(read_json(path) if path.exists() else V15_SPEC, indent=2, sort_keys=True))
