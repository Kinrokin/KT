from __future__ import annotations

import json

from v13_admission_common import build_hat_utility_gate, repo_root


def main() -> int:
    receipt = build_hat_utility_gate(repo_root())
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["claim_ceiling_preserved"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
