from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Iterable, Set


NUMERIC_STRING = re.compile(r"^\s*-?\d+(\.\d+)?\s*$")


def _iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def _contains_numeric_semantics(obj: Any, *, allow_keys: Set[str]) -> bool:
    if isinstance(obj, bool):
        return False
    if isinstance(obj, (int, float)):
        return True
    if isinstance(obj, str):
        return NUMERIC_STRING.match(obj) is not None
    if isinstance(obj, list):
        return any(_contains_numeric_semantics(x, allow_keys=allow_keys) for x in obj)
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in allow_keys:
                continue
            if _contains_numeric_semantics(value, allow_keys=allow_keys):
                return True
        return False
    return False


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate observer-only JSONL contains no numeric semantics outside identifier fields."
    )
    parser.add_argument("path", help="Path to observer_only.jsonl")
    parser.add_argument(
        "--allow-key",
        action="append",
        default=[],
        help="Key names that may contain numeric identifiers (repeatable).",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    allow_keys = {
        "epoch_id",
        "epoch_hash",
        "schema",
        "dataset_build_id",
        "epoch_root",
        "run_id",
        "artifact_ref",
        "row_id",
    }
    allow_keys.update(args.allow_key or [])

    failures = 0
    for idx, record in enumerate(_iter_jsonl(Path(args.path)), start=1):
        if _contains_numeric_semantics(record, allow_keys=allow_keys):
            print(f"numeric semantics detected at line {idx}")
            failures += 1
            if failures >= 10:
                break

    if failures:
        raise SystemExit(f"FAIL: numeric semantics detected in {failures} rows")
    print("PASS: no numeric semantics detected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
