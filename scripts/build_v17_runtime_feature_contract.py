from __future__ import annotations

from v17_canary_coalition_common import build_v17_config, load_v16, write_json


def main() -> int:
    for path, data in build_v17_config(load_v16()).items():
        if "feature_contract" in path.name or "fallback_policy" in path.name:
            write_json(path, data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
