from __future__ import annotations

from v17_canary_coalition_common import build_v18_atlas, load_v16, write_json


def main() -> int:
    for path, data in build_v18_atlas(load_v16()).items():
        write_json(path, data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
