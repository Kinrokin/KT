from __future__ import annotations

from typing import Any, Dict, List

from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import sha256_json


def build_judgement(*, job: Dict[str, Any], dataset: Dict[str, Any]) -> Dict[str, Any]:
    schema_file = "fl3/kt.factory.judgement.v1.json"
    from schemas.schema_files import schema_version_hash  # type: ignore

    accepted: List[str] = ["0"]
    rejected: List[str] = []
    record = {
        "schema_id": "kt.factory.judgement.v1",
        "schema_version_hash": schema_version_hash(schema_file),
        "judgement_id": "",
        "job_id": job["job_id"],
        "dataset_id": dataset["dataset_id"],
        "accepted_row_ids": accepted,
        "rejected_row_ids": rejected,
        "judge_ref": "stub",
        "created_at": utc_now_z(),
    }
    record["judgement_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "judgement_id"}})
    return record

