from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v15_oracle_harvest_common import base_preservation_preferences, oracle_gap_matrix, pairwise_preferences, route_value_rows, write_jsonl


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("admission/route_value_training_rows.jsonl")
    gaps = oracle_gap_matrix()
    rows = write_jsonl(out, route_value_rows(pairwise_preferences(gaps), base_preservation_preferences(gaps)))
    print(json.dumps({"rows": len(rows), "out": out.as_posix()}, sort_keys=True))
