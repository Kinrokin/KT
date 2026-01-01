from __future__ import annotations


def remaining_millis(*, ceiling_millis: int, used_millis: int) -> int:
    if ceiling_millis < 0:
        raise ValueError("ceiling_millis must be >= 0")
    if used_millis < 0:
        raise ValueError("used_millis must be >= 0")
    return ceiling_millis - used_millis

