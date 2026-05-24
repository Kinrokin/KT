from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compute verified work per token.")
    parser.add_argument("input_json", type=Path)
    args = parser.parse_args(argv)
    data = json.loads(args.input_json.read_text(encoding="utf-8-sig"))
    verified_work = float(data.get("verified_work", 0))
    token_count = max(1.0, float(data.get("token_count", 0)))
    print(
        json.dumps(
            {
                "schema_id": "kt.benchmark.verified_work_per_token_scorecard.v1",
                "verified_work": verified_work,
                "token_count": token_count,
                "verified_work_per_token": verified_work / token_count,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
