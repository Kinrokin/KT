from __future__ import annotations

def utc_now_z() -> str:
    """
    Deterministic timestamp for factory-lane artifacts.

    FL4/MRT-0 determinism requires that job_dir artifact bytes be stable across reruns.
    We therefore forbid wall-clock time in canonical factory outputs and use a fixed,
    schema-compatible UTC timestamp.
    """
    return "1970-01-01T00:00:00Z"
