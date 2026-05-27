from __future__ import annotations

import argparse
import json

from v13_admission_common import run_v13_superlane


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-clean", action="store_true", help="Use the pre-mutation clean audit state for truth pin replay.")
    args = parser.parse_args()
    receipt = run_v13_superlane(audit_clean=True if args.audit_clean else None)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if not receipt.get("blockers") else 2


if __name__ == "__main__":
    raise SystemExit(main())
