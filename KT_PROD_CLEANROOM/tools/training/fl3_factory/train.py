from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from tools.training.fl3_factory.hypotheses import build_policy_bundles
from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import canonical_json, repo_root_from, sha256_bytes, sha256_json
from tools.verification.fl3_validators import FL3ValidationError


def _schema_hash(schema_file: str) -> str:
    from schemas.schema_files import schema_version_hash  # type: ignore

    return schema_version_hash(schema_file)


def build_train_manifest(*, job: Dict[str, Any], dataset: Dict[str, Any], out_dir: Path) -> Dict[str, Any]:
    """
    FL4 / MRT-0 (AdapterType.A-only) "train" phase.

    This phase is metabolism proof, not neural weight training:
    - no gradients
    - no weights
    - no safetensors
    - deterministic generation of policy bundles (kt.policy_bundle.v1)
    """
    training_mode = str(job.get("training_mode"))
    if training_mode != "head_only":
        # Canonical FL4 lane is AdapterType.A-only; refuse weight-bearing modes.
        raise FL3ValidationError("MRT-0 requires training_mode=head_only (fail-closed)")

    seed = int(job.get("seed", 0))
    mode = str(job.get("mode", "SMOKE"))
    count = 12 if mode == "SMOKE" else 48

    parent_hash = str(dataset.get("dataset_id", "0" * 64))
    bundles = build_policy_bundles(job_id=str(job["job_id"]), seed=seed, parent_hash=parent_hash, count=count)

    hyp_dir = out_dir / "hypotheses"
    hyp_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = hyp_dir / "policy_bundles.jsonl"

    # Deterministic ordering: build_policy_bundles sorts by bundle_id.
    lines: List[str] = [canonical_json(b) for b in bundles]
    jsonl_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    artifact_hash = sha256_bytes(jsonl_path.read_bytes())
    repo_root = repo_root_from(Path(__file__))
    artifact_rel = jsonl_path.resolve().relative_to(repo_root.resolve()).as_posix()

    record: Dict[str, Any] = {
        "schema_id": "kt.factory.train_manifest.v1",
        "schema_version_hash": _schema_hash("fl3/kt.factory.train_manifest.v1.json"),
        "train_id": "",
        "job_id": job["job_id"],
        "dataset_id": dataset["dataset_id"],
        "base_model_id": job["base_model_id"],
        "training_mode": training_mode,
        "output_bundle": {"artifact_path": artifact_rel, "artifact_hash": artifact_hash},
        "created_at": utc_now_z(),
    }
    record["train_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "train_id"}})
    return record

