from __future__ import annotations

import argparse

from v16_crossroad_shadow_common import repo_root, validate_functional_implementation_data, write_json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="reports/v16_functional_implementation_receipt.json")
    args = parser.parse_args()
    root = repo_root()
    receipt = validate_functional_implementation_data(root)
    write_json(root / args.out, receipt)
    return 0 if receipt["gate_pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
