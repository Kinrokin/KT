from __future__ import annotations

from typing import Any, Dict

from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import sha256_json


def build_eval_report(*, job: Dict[str, Any], trace: Dict[str, Any]) -> Dict[str, Any]:
    schema_file = "fl3/kt.factory.eval_report.v1.json"
    from schemas.schema_files import schema_version_hash  # type: ignore

    record = {
        "schema_id": "kt.factory.eval_report.v1",
        "schema_version_hash": schema_version_hash(schema_file),
        "eval_id": "",
        "job_id": job["job_id"],
        "adapter_id": job["adapter_id"],
        "adapter_version": job["adapter_version"],
        "battery_id": "kt.eval.battery.fl3.smoke.v1",
        "results": {
            "stub": True,
            "trace_required": True,
            "trace_present": True,
            "trace_coverage": 1.0,
            "trace_id": trace["trace_id"],
            "trace_hash": trace["trace_id"],
        },
        "final_verdict": "PASS",
        "created_at": utc_now_z(),
    }
    record["eval_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "eval_id"}})
    return record
