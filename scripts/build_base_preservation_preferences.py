from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v15_oracle_harvest_common import base_preservation_preferences, oracle_gap_matrix, write_jsonl


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("admission/base_preservation_preferences.jsonl")
    rows = write_jsonl(out, base_preservation_preferences(oracle_gap_matrix()))
    print(json.dumps({"rows": len(rows), "out": out.as_posix()}, sort_keys=True))
