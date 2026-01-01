from __future__ import annotations


def remaining_bytes(*, ceiling_bytes: int, used_bytes: int) -> int:
    if ceiling_bytes < 0:
        raise ValueError("ceiling_bytes must be >= 0")
    if used_bytes < 0:
        raise ValueError("used_bytes must be >= 0")
    return ceiling_bytes - used_bytes

