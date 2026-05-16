from __future__ import annotations

import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.highway_common import cli


if __name__ == "__main__":
    raise SystemExit(cli("highway_posture_sync"))
