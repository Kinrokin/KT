from __future__ import annotations


def remaining_tokens(*, ceiling_tokens: int, used_tokens: int) -> int:
    if ceiling_tokens < 0:
        raise ValueError("ceiling_tokens must be >= 0")
    if used_tokens < 0:
        raise ValueError("used_tokens must be >= 0")
    return ceiling_tokens - used_tokens

