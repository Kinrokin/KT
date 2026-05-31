from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v141_truth_common import read_json, repo_root, structure_bound_receipt


def classify(dataset_label_used: bool, math_act_features_used: bool) -> str:
    if dataset_label_used and not math_act_features_used:
        return "STATIC_TASK_FAMILY_BOUND"
    if dataset_label_used and math_act_features_used:
        return "HYBRID_LABEL_AND_STRUCTURE_BOUND"
    if not dataset_label_used and math_act_features_used:
        return "STRUCTURE_BOUND"
    return "UNKNOWN_BLOCKED"


if __name__ == "__main__":
    root = repo_root()
    path = root / "reports/v14_structure_bound_downgrade_receipt.json"
    print(json.dumps(read_json(path) if path.exists() else structure_bound_receipt(), indent=2, sort_keys=True))
