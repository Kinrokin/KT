from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import sha256_json, sha256_text


def build_train_manifest(*, job: Dict[str, Any], dataset: Dict[str, Any], out_dir: Path) -> Dict[str, Any]:
    schema_file = "fl3/kt.factory.train_manifest.v1.json"
    from schemas.schema_files import schema_version_hash  # type: ignore

    # Deterministic fake "weights bundle" for smoke: content is stable per job_id.
    bundle_dir = out_dir / "bundle"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    weights_path = bundle_dir / "weights.stub"
    weights_path.write_text(f"stub-weights:{job['job_id']}\n", encoding="utf-8")
    artifact_hash = sha256_text(weights_path.read_text(encoding="utf-8"))

    record = {
        "schema_id": "kt.factory.train_manifest.v1",
        "schema_version_hash": schema_version_hash(schema_file),
        "train_id": "",
        "job_id": job["job_id"],
        "dataset_id": dataset["dataset_id"],
        "base_model_id": job["base_model_id"],
        "training_mode": job["training_mode"],
        "output_bundle": {"artifact_path": str(weights_path.as_posix()), "artifact_hash": artifact_hash},
        "created_at": utc_now_z(),
    }
    record["train_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "train_id"}})
    return record

