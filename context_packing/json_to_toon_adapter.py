from __future__ import annotations

import json
from typing import Any


def to_toon(value: Any, *, indent: int = 0) -> str:
    """Render a small deterministic TOON-like view; JSON remains canonical."""
    prefix = "  " * indent
    if isinstance(value, dict):
        rows: list[str] = []
        for key in sorted(value):
            rendered = to_toon(value[key], indent=indent + 1)
            if "\n" in rendered:
                rows.append(f"{prefix}{key}:")
                rows.append(rendered)
            else:
                rows.append(f"{prefix}{key}: {rendered.strip()}")
        return "\n".join(rows)
    if isinstance(value, list):
        rows = []
        for item in value:
            rendered = to_toon(item, indent=indent + 1)
            rows.append(f"{prefix}- {rendered.strip()}" if "\n" not in rendered else f"{prefix}-\n{rendered}")
        return "\n".join(rows)
    return prefix + json.dumps(value, sort_keys=True, ensure_ascii=True)


def json_text_to_toon(text: str) -> str:
    return to_toon(json.loads(text))


if __name__ == "__main__":
    import sys

    print(json_text_to_toon(sys.stdin.read()))
