from __future__ import annotations

import json
from pathlib import Path
from typing import Dict


def write_report(path: Path, *, result: Dict[str, object], deltas: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "result": result,
        "deltas": deltas,
    }
    path.write_text(json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
