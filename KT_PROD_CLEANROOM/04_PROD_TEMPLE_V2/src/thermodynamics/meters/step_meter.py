from __future__ import annotations


def remaining_steps(*, ceiling_steps: int, used_steps: int) -> int:
    if ceiling_steps < 0:
        raise ValueError("ceiling_steps must be >= 0")
    if used_steps < 0:
        raise ValueError("used_steps must be >= 0")
    return ceiling_steps - used_steps


def remaining_branches(*, ceiling_branches: int, used_branches: int) -> int:
    if ceiling_branches < 0:
        raise ValueError("ceiling_branches must be >= 0")
    if used_branches < 0:
        raise ValueError("used_branches must be >= 0")
    return ceiling_branches - used_branches

