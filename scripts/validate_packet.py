from __future__ import annotations

import json
import sys
from pathlib import Path


REQUIRED = ["PACKET_MANIFEST.json", "SHA256_MANIFEST.json", "README.md"]


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    missing = [item for item in REQUIRED if not (root / item).exists()]
    bad: list[str] = []
    for path in root.rglob("*.json"):
        try:
            json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception as exc:  # pragma: no cover - diagnostic path
            bad.append(f"{path}: {exc}")
    if missing or bad:
        print("PACKET_VALIDATE FAIL")
        if missing:
            print("missing", missing)
        if bad:
            print("\n".join(bad[:20]))
        return 1
    print("PACKET_VALIDATE PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
