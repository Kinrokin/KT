from __future__ import annotations

import json

from accountability_common import build_state_diff_contract, repo_root


if __name__ == "__main__":
    print(json.dumps(build_state_diff_contract(repo_root()), indent=2, sort_keys=True))
