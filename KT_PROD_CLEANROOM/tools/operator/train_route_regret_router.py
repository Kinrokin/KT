from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Emit a deterministic route-regret router training plan.")
    parser.add_argument("matrix_json", type=Path)
    parser.add_argument("output_json", type=Path)
    args = parser.parse_args(argv)
    matrix = json.loads(args.matrix_json.read_text(encoding="utf-8-sig"))
    plan = {
        "schema_id": "kt.router.route_regret_router_training_plan.v1",
        "source_matrix": args.matrix_json.as_posix(),
        "sample_count": matrix.get("sample_count", len(matrix.get("rows", []))),
        "objective": "minimize_route_regret_and_verified_work_per_token_loss",
        "training_authorizes_router_superiority": False,
        "requires_shadow_eval_before_claim": True,
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.output_json.as_posix())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
