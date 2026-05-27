from __future__ import annotations

import json

from v13_admission_common import replay_v12_specialist_route_derivation, repo_root


def main() -> int:
    receipt = replay_v12_specialist_route_derivation(repo_root())
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["replay_status"].startswith("PASS") else 2


if __name__ == "__main__":
    raise SystemExit(main())
