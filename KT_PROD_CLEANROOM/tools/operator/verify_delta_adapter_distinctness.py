from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.compact_hat_route_regret_scar_repair_v1 import verify_delta_distinctness


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify delta adapter distinctness and failure mapping.")
    parser.add_argument("failure_json", type=Path)
    parser.add_argument("delta_json", type=Path)
    parser.add_argument("--parent-hash", required=True)
    parser.add_argument("--delta-hash", required=True)
    args = parser.parse_args(argv)
    failure_rows = json.loads(args.failure_json.read_text(encoding="utf-8-sig"))
    delta_rows = json.loads(args.delta_json.read_text(encoding="utf-8-sig"))
    receipt = verify_delta_distinctness(
        failure_rows=failure_rows,
        delta_rows=delta_rows,
        parent_adapter_hash=args.parent_hash,
        delta_adapter_hash=args.delta_hash,
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["scar_learning_claim_allowed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
