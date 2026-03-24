from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional


DEFAULT_ENV_VAR = "KT_RUNTIME_TELEMETRY_PATH"


def telemetry_now_ms() -> int:
    return int(time.time() * 1000)


def _telemetry_path(path: Optional[str | Path] = None) -> Optional[Path]:
    raw = str(path).strip() if path is not None else os.environ.get(DEFAULT_ENV_VAR, "").strip()
    if not raw:
        return None
    return Path(raw).expanduser().resolve()


def build_telemetry_envelope(
    *,
    surface_id: str,
    zone: str,
    event_type: str,
    start_ts: int,
    end_ts: int,
    result_status: str,
    provider_id: str = "",
    policy_applied: str = "",
    budget_consumed: Optional[Dict[str, Any]] = None,
    receipt_ref: str = "",
    failure_artifact_ref: str = "",
    trace_id: str = "",
    span_id: str = "",
    request_id: str = "",
) -> Dict[str, Any]:
    final_trace_id = str(trace_id).strip() or uuid.uuid4().hex
    final_span_id = str(span_id).strip() or uuid.uuid4().hex[:16]
    final_request_id = str(request_id).strip() or uuid.uuid4().hex
    return {
        "trace_id": final_trace_id,
        "span_id": final_span_id,
        "request_id": final_request_id,
        "surface_id": str(surface_id).strip(),
        "zone": str(zone).strip(),
        "event_type": str(event_type).strip(),
        "start_ts": int(start_ts),
        "end_ts": int(end_ts),
        "latency_ms": max(0, int(end_ts) - int(start_ts)),
        "provider_id": str(provider_id).strip(),
        "budget_consumed": dict(budget_consumed or {}),
        "policy_applied": str(policy_applied).strip(),
        "result_status": str(result_status).strip(),
        "receipt_ref": str(receipt_ref).strip(),
        "failure_artifact_ref": str(failure_artifact_ref).strip(),
    }


def emit_runtime_telemetry(
    *,
    surface_id: str,
    zone: str,
    event_type: str,
    start_ts: int,
    end_ts: int,
    result_status: str,
    provider_id: str = "",
    policy_applied: str = "",
    budget_consumed: Optional[Dict[str, Any]] = None,
    receipt_ref: str = "",
    failure_artifact_ref: str = "",
    trace_id: str = "",
    span_id: str = "",
    request_id: str = "",
    path: Optional[str | Path] = None,
) -> Optional[Dict[str, Any]]:
    telemetry_path = _telemetry_path(path)
    payload = build_telemetry_envelope(
        surface_id=surface_id,
        zone=zone,
        event_type=event_type,
        start_ts=start_ts,
        end_ts=end_ts,
        result_status=result_status,
        provider_id=provider_id,
        policy_applied=policy_applied,
        budget_consumed=budget_consumed,
        receipt_ref=receipt_ref,
        failure_artifact_ref=failure_artifact_ref,
        trace_id=trace_id,
        span_id=span_id,
        request_id=request_id,
    )
    if telemetry_path is None:
        return payload
    telemetry_path.parent.mkdir(parents=True, exist_ok=True)
    with telemetry_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, sort_keys=True, ensure_ascii=True) + "\n")
    return payload
