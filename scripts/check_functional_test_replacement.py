from __future__ import annotations

import argparse
import json

from v14_omni_common import scan_functional_replacement


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--receipt", default="reports/v14_placeholder_replacement_receipt.json")
    args = parser.parse_args()
    receipt = scan_functional_replacement(__import__("pathlib").Path(args.root).resolve())
    if args.receipt != "reports/v14_placeholder_replacement_receipt.json":
        from accountability_common import write_json
        write_json(__import__("pathlib").Path(args.root).resolve() / args.receipt, receipt)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["gate_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
