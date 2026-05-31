from __future__ import annotations

from v16_crossroad_shadow_common import write_all_outputs


def main() -> int:
    summary = write_all_outputs()
    return 0 if not summary["blockers"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
