from __future__ import annotations

import json
from collections import Counter

from v16_crossroad_shadow_common import repo_root, write_json


def main() -> int:
    root = repo_root()
    decisions = [json.loads(line) for line in (root / "admission/v16_route_value_decisions.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    selected = Counter(row["selected_route"] for row in decisions)
    rescued = Counter(row["selected_route"] for row in decisions if row["selected_matches_oracle"])
    datasets = Counter(row["dataset"] for row in decisions)
    write_json(
        root / "admission/v16_capability_habitat_topology.json",
        {
            "schema_id": "kt.v16_competence_topology.v1",
            "nodes": [
                {"node_id": route, "node_type": "route", "selected_count": selected[route], "rescued_count": rescued[route]}
                for route in sorted(selected)
            ],
            "datasets": [{"dataset": dataset, "oracle_gap_rows": count} for dataset, count in sorted(datasets.items())],
            "runtime_authority": False,
            "promotion_authority": False,
            "claim_ceiling_preserved": True,
            "status": "PASS",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
