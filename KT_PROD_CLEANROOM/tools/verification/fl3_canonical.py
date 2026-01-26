from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Tuple


def canonical_json(obj: Any) -> str:
    # Must remain stable across platforms for hash surfaces used in LAW_BUNDLE and FL3 artifacts.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_json(obj: Any) -> str:
    return sha256_text(canonical_json(obj))


def repo_root_from(path: Path) -> Path:
    p = path.resolve()
    for parent in [p] + list(p.parents):
        if (parent / "KT_PROD_CLEANROOM").is_dir():
            return parent
    raise RuntimeError("Unable to locate repo root (expected KT_PROD_CLEANROOM/)")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def iter_paths_sorted(paths: Iterable[Path]) -> Tuple[Path, ...]:
    return tuple(sorted((p for p in paths), key=lambda x: x.as_posix()))

