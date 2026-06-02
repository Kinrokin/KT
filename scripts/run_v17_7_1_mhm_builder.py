from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.v17_7_1_mhm_common import build_all, write_json


def main() -> None:
    summary = build_all()
    write_json(Path("reports/v17_7_1_builder_summary.json"), summary)
    print(summary["outcome"])


if __name__ == "__main__":
    main()
