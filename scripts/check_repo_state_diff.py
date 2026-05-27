from __future__ import annotations

import json
import argparse

from accountability_common import build_state_diff_contract, repo_root, read_json
from v14_omni_common import build_state_diff


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--v14", action="store_true")
    args = parser.parse_args()
    root = repo_root()
    if args.v14:
        build_state_diff(root)
        payload = read_json(root / "reports/v14_repo_state_diff_contract.json")
    elif (root / "reports/repo_state_diff_contract.json").exists():
        payload = read_json(root / "reports/repo_state_diff_contract.json")
    else:
        payload = build_state_diff_contract(root)
    print(json.dumps(payload, indent=2, sort_keys=True))
