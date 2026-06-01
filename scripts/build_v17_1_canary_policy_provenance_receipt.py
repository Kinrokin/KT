from __future__ import annotations

from v17_1_canary_repair_common import build_all_outputs


if __name__ == "__main__":
    raise SystemExit(0 if build_all_outputs()["blockers"] == [] else 2)
