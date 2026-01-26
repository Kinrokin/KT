from __future__ import annotations

from typing import Any, Dict, List

from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import sha256_json


def build_dataset(*, job: Dict[str, Any]) -> Dict[str, Any]:
    schema_file = "fl3/kt.factory.dataset.v1.json"
    from schemas.schema_files import schema_version_hash  # type: ignore

    rows: List[Dict[str, Any]] = [
        {"prompt": f"stub:{job['adapter_id']}", "response": "stub", "seed": job["seed"]},
    ]
    record = {
        "schema_id": "kt.factory.dataset.v1",
        "schema_version_hash": schema_version_hash(schema_file),
        "dataset_id": "",
        "job_id": job["job_id"],
        "rows": rows,
        "created_at": utc_now_z(),
    }
    record["dataset_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "dataset_id"}})
    return record

