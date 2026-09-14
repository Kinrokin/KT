from __future__ import annotations

import os
from pathlib import Path


WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def is_link_or_reparse_point(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        try:
            attributes = int(getattr(os.lstat(path), "st_file_attributes", 0))
        except FileNotFoundError:
            attributes = 0
        return bool(attributes & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT)
    except OSError:
        return True


def assert_no_link_or_reparse_path(path: Path, *, label: str) -> None:
    if not path.is_absolute():
        raise RuntimeError(f"{label} must be absolute (fail-closed)")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        if is_link_or_reparse_point(current):
            raise RuntimeError(f"{label} contains link/reparse point (fail-closed)")


__all__ = ["assert_no_link_or_reparse_path", "is_link_or_reparse_point"]
