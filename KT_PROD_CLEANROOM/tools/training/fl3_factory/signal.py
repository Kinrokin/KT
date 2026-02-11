from __future__ import annotations

from typing import Any, Dict

from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_validators import validate_schema_bound_object


def build_signal_quality(
    *,
    adapter_id: str,
    adapter_version: str,
    risk_estimate: float,
    governance_strikes: int,
    status: str,
) -> Dict[str, Any]:
    from schemas.schema_files import schema_version_hash  # type: ignore

    record = {
        "schema_id": "kt.signal_quality.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.signal_quality.v1.json"),
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "risk_estimate": float(risk_estimate),
        "governance_strikes": int(governance_strikes),
        "status": status,
        "created_at": utc_now_z(),
    }
    # Validate before returning so callers can fail-closed early.
    validate_schema_bound_object(record)
    return record

