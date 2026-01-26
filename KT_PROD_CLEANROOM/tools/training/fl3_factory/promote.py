from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.training.fl3_factory.timeutil import utc_now_z
from tools.training.fl3_factory.io import read_json_object
from tools.verification.fl3_canonical import sha256_json
from tools.verification.fl3_validators import FL3ValidationError
from tools.training.fl3_factory.trace import verify_reasoning_trace


def decide_promotion(
    *,
    job: Dict[str, Any],
    eval_report: Dict[str, Any],
    trace_path: Optional[Path],
) -> str:
    """
    FL3 reasoning-trace law (minimal): promotion is only possible when a valid trace exists.

    Fail-closed semantics:
    - missing trace => cannot promote (REJECT)
    - trace tamper (hash mismatch) => error (contract failure)
    """
    if eval_report.get("final_verdict") != "PASS":
        return "REJECT"
    # Only sovereign mode is eligible for promotion in the stub factory.
    if job.get("mode") != "SOVEREIGN":
        return "REJECT"

    if trace_path is None or not trace_path.exists():
        return "REJECT"

    trace = read_json_object(trace_path)
    verify_reasoning_trace(trace)  # raises on tamper/mismatch

    results = eval_report.get("results") or {}
    if isinstance(results, dict):
        if results.get("trace_required") is True and float(results.get("trace_coverage", 0.0)) < 1.0:
            return "REJECT"
        # If an eval report binds a trace id, it must match the trace artifact.
        if "trace_id" in results and results.get("trace_id") != trace.get("trace_id"):
            raise FL3ValidationError("eval_report trace_id mismatch (fail-closed)")

    return "PROMOTE"


def build_promotion(*, job: Dict[str, Any], decision: str, reasons: List[str], links: Dict[str, Any]) -> Dict[str, Any]:
    schema_file = "fl3/kt.factory.promotion.v1.json"
    from schemas.schema_files import schema_version_hash  # type: ignore

    record = {
        "schema_id": "kt.factory.promotion.v1",
        "schema_version_hash": schema_version_hash(schema_file),
        "promotion_id": "",
        "job_id": job["job_id"],
        "decision": decision,
        "reasons": sorted(reasons),
        "links": links,
        "created_at": utc_now_z(),
    }
    record["promotion_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "promotion_id"}})
    return record
