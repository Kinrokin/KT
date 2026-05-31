from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v141_truth_common import DATASET_LABEL_BLIND_REQUIREMENTS, read_json, repo_root


if __name__ == "__main__":
    root = repo_root()
    path = root / "admission/dataset_label_blind_routing_requirements.json"
    print(json.dumps(read_json(path) if path.exists() else DATASET_LABEL_BLIND_REQUIREMENTS, indent=2, sort_keys=True))
