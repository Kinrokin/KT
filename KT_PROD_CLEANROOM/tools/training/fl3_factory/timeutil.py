from __future__ import annotations

from datetime import datetime, timezone


def utc_now_z() -> str:
    # Match schema validators: UTC with Z suffix, second resolution.
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

