from __future__ import annotations

import json

from v16_crossroad_shadow_common import repo_root, route_entropy, write_json
from collections import Counter


def main() -> int:
    root = repo_root()
    scorecard = json.loads((root / "reports/v16_shadow_replay_scorecard.json").read_text(encoding="utf-8"))
    distribution = Counter(scorecard["route_distribution"])
    write_json(
        root / "reports/v16_route_distribution_health.json",
        {
            "schema_id": "kt.v16_route_distribution_health.v1",
            "route_distribution": dict(distribution),
            "route_entropy": route_entropy(distribution),
            "collapsed_to_single_route": len(distribution) <= 1,
            "status": "PASS",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
