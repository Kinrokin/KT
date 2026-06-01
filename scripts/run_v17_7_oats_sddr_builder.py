from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.v17_7_oats_sddr_common import build_all, write_json


def main() -> None:
    result = build_all()
    write_json(Path("reports/v17_7_builder_summary.json"), result)
    print(result["outcome"])


if __name__ == "__main__":
    main()
