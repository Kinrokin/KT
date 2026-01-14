from __future__ import annotations

import json
from pathlib import Path


def normalize_jsonl(in_path: Path, out_path: Path) -> None:
    """
    Normalize potentially mixed/pretty JSON into strict JSONL (one object per line).
    - If already valid JSONL, emits unchanged (ensures trailing newline).
    - If valid JSON array or object, re-emits as JSONL.
    """
    text = in_path.read_text(encoding="utf-8").strip()
    if not text:
        out_path.write_text("", encoding="utf-8")
        return

    # Attempt to treat as JSONL first.
    try:
        lines = text.splitlines()
        for line in lines:
            if line.strip():
                json.loads(line)
        out_path.write_text("\n".join([ln for ln in lines if ln.strip()]) + "\n", encoding="utf-8")
        return
    except Exception:
        pass

    # Fallback: parse as JSON and emit as JSONL.
    obj = json.loads(text)
    with out_path.open("w", encoding="utf-8", newline="\n") as handle:
        if isinstance(obj, list):
            for entry in obj:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        else:
            handle.write(json.dumps(obj, ensure_ascii=False) + "\n")
