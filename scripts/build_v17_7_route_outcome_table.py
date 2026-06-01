from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.v17_7_oats_sddr_common import build_all


if __name__ == "__main__":
    build_all()
    print("admission/v17_7_route_outcome_table.jsonl")
