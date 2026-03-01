from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.schema_files import schema_version_hash  # noqa: E402
from tools.training.training_admission_gate import ensure_training_admission_receipt  # noqa: E402
from tools.verification.fl3_canonical import sha256_json  # noqa: E402


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _mk_jobspec() -> dict:
    job = {
        "schema_id": "kt.factory.jobspec.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.jobspec.v1.json"),
        "job_id": "",
        "adapter_id": "lobe.architect.v1",
        "adapter_version": "1",
        "role": "ARCHITECT",
        "mode": "SMOKE",
        "run_kind": "STANDARD",
        "base_model_id": "mistral-7b",
        "training_mode": "head_only",
        "seed": 123,
        "export_shadow_root": "KT_PROD_CLEANROOM/exports/adapters_shadow/_tests",
        "export_promoted_root": "KT_PROD_CLEANROOM/exports/adapters/_tests",
    }
    job["job_id"] = sha256_json({k: v for k, v in job.items() if k != "job_id"})
    return job


def test_training_admission_gate_is_deterministic(tmp_path: Path) -> None:
    repo_root = _REPO_ROOT
    job = _mk_jobspec()
    job_path = tmp_path / "job.json"
    job_dir = tmp_path / "job_dir"
    _write_json(job_path, job)

    r1 = ensure_training_admission_receipt(
        repo_root=repo_root,
        job_path=job_path,
        job_dir=job_dir,
        lane_id="TEST_LANE",
    )
    text1 = (job_dir / "training_admission_receipt.json").read_text(encoding="utf-8")

    r2 = ensure_training_admission_receipt(
        repo_root=repo_root,
        job_path=job_path,
        job_dir=job_dir,
        lane_id="TEST_LANE",
    )
    text2 = (job_dir / "training_admission_receipt.json").read_text(encoding="utf-8")

    assert r1 == r2
    assert text1 == text2
    assert r1["schema_id"] == "kt.training_admission_receipt.v1"
    assert r1["decision"] == "PASS"
    assert r1["admission_receipt_id"] == r2["admission_receipt_id"]

