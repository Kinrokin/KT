from __future__ import annotations

from pathlib import Path
from typing import Iterable, Sequence

from tools.verification.fl3_validators import FL3ValidationError


def enforce_all_or_none_exist(paths: Sequence[Path], *, label: str) -> None:
    """
    WORM safety: multi-file artifacts must not exist in a partial state.
    If any path exists, all paths must exist; otherwise fail-closed.
    """
    exists = [p.exists() for p in paths]
    if any(exists) and not all(exists):
        present = [p.as_posix() for p, e in zip(paths, exists) if e]
        missing = [p.as_posix() for p, e in zip(paths, exists) if not e]
        raise FL3ValidationError(
            f"FAIL_CLOSED: {label} exists in partial state. present={present} missing={missing}"
        )


def write_bytes_worm(*, path: Path, data: bytes, label: str) -> None:
    """
    Create-once (WORM) write. If file exists, allow only byte-identical no-op.
    """
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        existing = path.read_bytes()
        if existing == data:
            return
        raise FL3ValidationError(f"FAIL_CLOSED: refusing to overwrite existing {label}: {path.as_posix()}")

    try:
        with path.open("xb") as handle:
            handle.write(data)
    except FileExistsError:
        existing = path.read_bytes()
        if existing == data:
            return
        raise FL3ValidationError(f"FAIL_CLOSED: refusing to overwrite existing {label}: {path.as_posix()}")


def write_text_worm(*, path: Path, text: str, label: str, encoding: str = "utf-8") -> None:
    write_bytes_worm(path=path, data=text.encode(encoding), label=label)


def write_many_text_worm(*, items: Iterable[tuple[Path, str, str]], label: str) -> None:
    """
    Convenience for writing a set of related text artifacts.
    items: iterable of (path, text, per-file-label).
    """
    for p, txt, item_label in items:
        write_text_worm(path=p, text=txt, label=f"{label}:{item_label}")

