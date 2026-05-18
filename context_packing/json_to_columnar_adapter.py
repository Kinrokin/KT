from __future__ import annotations

import json
from typing import Any


def flatten(value: Any, prefix: str = "") -> list[tuple[str, str]]:
    if isinstance(value, dict):
        rows: list[tuple[str, str]] = []
        for key in sorted(value):
            rows.extend(flatten(value[key], f"{prefix}.{key}" if prefix else str(key)))
        return rows
    if isinstance(value, list):
        rows = []
        for index, item in enumerate(value):
            rows.extend(flatten(item, f"{prefix}[{index}]"))
        return rows
    return [(prefix, json.dumps(value, sort_keys=True, ensure_ascii=True))]


def json_text_to_columnar(text: str) -> str:
    rows = flatten(json.loads(text))
    return "\n".join(f"{path}\t{value}" for path, value in rows)


if __name__ == "__main__":
    import sys

    print(json_text_to_columnar(sys.stdin.read()))
