from __future__ import annotations

import json

from scripts import replay_v17_7_4_g2_bound_raw_output_extraction as replay


def main() -> int:
    _, rows, _ = replay.load_bound_rows()
    summary, table, audit = replay.build_cheapest_correct_v2(rows)
    replay.write_json(replay.ROOT / "reports" / "v17_7_4_cheapest_correct_route_simulation_v2.json", summary)
    replay.write_jsonl(replay.ROOT / "reports" / "v17_7_4_cheapest_correct_route_table_v2.jsonl", table)
    replay.write_json(replay.ROOT / "reports" / "v17_7_4_pre_generation_route_feature_audit.json", audit)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
