from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v141_truth_common import V14_EVIDENCE, read_json, repo_root


if __name__ == "__main__":
    root = repo_root()
    path = root / "evidence/V14_KNOWN_MEASURED_RESULT.json"
    print(json.dumps(read_json(path) if path.exists() else V14_EVIDENCE, indent=2, sort_keys=True))
