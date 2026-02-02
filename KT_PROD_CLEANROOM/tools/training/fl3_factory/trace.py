from __future__ import annotations

from typing import Any, Dict

from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import sha256_json
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object


def build_reasoning_trace(*, job_id: str, final_output_hash: str, steps: list[dict] | None = None) -> Dict[str, Any]:
    from schemas.schema_files import schema_version_hash  # type: ignore

    record = {
        "schema_id": "kt.reasoning_trace.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.reasoning_trace.v1.json"),
        "trace_id": "",
        "steps": steps or [{"type": "STUB", "job_id": job_id}],
        "final_output_hash": final_output_hash,
        "created_at": utc_now_z(),
    }
    record["trace_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "trace_id"}})
    return record


def verify_reasoning_trace(trace: Dict[str, Any]) -> None:
    validate_schema_bound_object(trace)
    if trace.get("schema_id") != "kt.reasoning_trace.v1":
        raise FL3ValidationError("trace schema_id mismatch (fail-closed)")
    expected = sha256_json({k: v for k, v in trace.items() if k not in {"created_at", "trace_id"}})
    if trace.get("trace_id") != expected:
        raise FL3ValidationError("trace_id mismatch (fail-closed)")

