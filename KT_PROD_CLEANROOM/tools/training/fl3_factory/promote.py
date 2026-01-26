from __future__ import annotations

from typing import Any, Dict, List

from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import sha256_json


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

