from __future__ import annotations

import argparse
import json
from pathlib import Path


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    seen: set[str] = set()
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"duplicate JSON key: {key}")
        seen.add(key)
        out[key] = value
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", default=["schemas", "reports", "registry", "packets"])
    args = parser.parse_args()
    checked = 0
    failures = []
    for raw in args.paths:
        path = Path(raw)
        candidates = [path] if path.is_file() else sorted(path.rglob("*.json")) if path.exists() else []
        for candidate in candidates:
            try:
                json.loads(candidate.read_text(encoding="utf-8-sig"), object_pairs_hook=reject_duplicate_keys)
                checked += 1
            except Exception as exc:  # noqa: BLE001
                failures.append({"path": candidate.as_posix(), "error": str(exc)})
    print(json.dumps({"schema_id": "kt.json_parse_gate.v1", "checked": checked, "failures": failures, "status": "PASS" if not failures else "FAIL"}, indent=2, sort_keys=True))
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
