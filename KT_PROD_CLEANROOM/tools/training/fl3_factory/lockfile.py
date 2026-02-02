from __future__ import annotations

import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from tools.verification.fl3_validators import FL3ValidationError


@contextmanager
def exclusive_lock(path: Path, *, timeout_s: float = 5.0, poll_s: float = 0.05) -> Iterator[None]:
    """
    Cross-platform lock using atomic create. Fail-closed on timeout.
    This is intentionally simple: FL3 budget state must be single-writer.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.time() + timeout_s
    fd = None
    while True:
        try:
            fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError:
            if time.time() >= deadline:
                raise FL3ValidationError(f"Unable to acquire lock (fail-closed): {path.as_posix()}")
            time.sleep(poll_s)
    try:
        os.write(fd, f"pid={os.getpid()}\n".encode("utf-8"))
        yield
    finally:
        try:
            os.close(fd)
        except Exception:
            pass
        try:
            path.unlink(missing_ok=True)  # py310+ supports missing_ok
        except TypeError:
            # py<3.8 compatibility not needed, but keep fail-safe
            if path.exists():
                path.unlink()

