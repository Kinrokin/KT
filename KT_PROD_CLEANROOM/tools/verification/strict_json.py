from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


class DuplicateKeyError(ValueError):
    pass


def loads_no_dupes(data: str) -> Any:
    def hook(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        obj: Dict[str, Any] = {}
        for k, v in pairs:
            if k in obj:
                raise DuplicateKeyError(f"Duplicate JSON key (fail-closed): {k!r}")
            obj[k] = v
        return obj

    return json.loads(data, object_pairs_hook=hook)


def load_no_dupes(path: Path) -> Any:
    return loads_no_dupes(path.read_text(encoding="utf-8"))

