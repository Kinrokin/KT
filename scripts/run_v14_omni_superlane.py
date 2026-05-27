from __future__ import annotations

import argparse
import json

from v14_omni_common import run_v14_superlane


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-clean", action="store_true", help="Treat the pre-mutation DCI clean-worktree check as already satisfied.")
    args = parser.parse_args()
    receipt = run_v14_superlane(audit_clean=True if args.audit_clean else None)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if not receipt.get("outcome", "").endswith("FAILED") and not receipt.get("outcome", "").startswith("KT_V14_BLOCKED") else 1


if __name__ == "__main__":
    raise SystemExit(main())
