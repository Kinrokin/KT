from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    bad = []
    for path in (ROOT / "packets").glob("**/*.zip"):
        rel = path.relative_to(ROOT).as_posix()
        if len(path.name) > 64 or any(ch.isupper() for ch in path.name):
            bad.append(rel)
    if bad:
        raise SystemExit(f"packet naming policy violation: {bad[:20]}")
    print(json.dumps({"schema_id": "kt.packet_name_length_check.v1", "status": "PASS"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
