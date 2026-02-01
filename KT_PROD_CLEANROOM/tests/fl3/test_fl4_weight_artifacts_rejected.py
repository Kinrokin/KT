from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.schema_files import schema_version_hash  # noqa: E402
from tools.training.fl3_factory.hashing import sha256_file_normalized  # noqa: E402
from tools.training.fl3_factory.run_job import EXIT_OK, main as run_job_main  # noqa: E402
from tools.verification.fl3_canonical import sha256_json  # noqa: E402
from tools.verification.fl3_meta_evaluator import FL3ValidationError, verify_job_dir  # noqa: E402


def _write_json(p: Path, obj: dict) -> None:
    p.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _mk_jobspec(*, export_shadow_root: str, export_promoted_root: str) -> dict:
    job = {
        "schema_id": "kt.factory.jobspec.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.jobspec.v1.json"),
        "job_id": "",
        "adapter_id": "fl4.weight_artifacts.rejected.v1",
        "adapter_version": "1",
        "role": "ARCHITECT",
        "mode": "SMOKE",
        "run_kind": "STANDARD",
        "base_model_id": "mistral-7b",
        "training_mode": "head_only",
        "seed": 42,
        "export_shadow_root": export_shadow_root,
        "export_promoted_root": export_promoted_root,
    }
    job["job_id"] = sha256_json({k: v for k, v in job.items() if k != "job_id"})
    return job


def _mk_contract(*, repo_root: Path, entrypoints: dict) -> dict:
    c = {
        "schema_id": "kt.factory.organ_contract.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.organ_contract.v1.json"),
        "contract_id": "",
        "entrypoints": entrypoints,
        "allowed_base_models": ["mistral-7b"],
        "allowed_training_modes": ["head_only"],
        "allowed_output_schemas": sorted(
            [
                "kt.factory.jobspec.v1",
                "kt.factory.dataset.v1",
                "kt.reasoning_trace.v1",
                "kt.factory.judgement.v1",
                "kt.factory.train_manifest.v1",
                "kt.policy_bundle.v1",
                "kt.factory.eval_report.v2",
                "kt.signal_quality.v1",
                "kt.immune_snapshot.v1",
                "kt.epigenetic_summary.v1",
                "kt.fitness_region.v1",
                "kt.factory.promotion.v1",
                "kt.factory.phase_trace.v1",
                "kt.hash_manifest.v1",
                "kt.factory.job_dir_manifest.v1",
            ]
        ),
        "allowed_export_roots": [
            "KT_PROD_CLEANROOM/exports/adapters",
            "KT_PROD_CLEANROOM/exports/adapters_shadow",
        ],
        "created_at": "1970-01-01T00:00:00Z",
    }
    c["contract_id"] = sha256_json({k: v for k, v in c.items() if k not in {"created_at", "contract_id"}})
    return c


@pytest.mark.parametrize("ext", [".ckpt", ".onnx", ".gguf"])
def test_canonical_lane_rejects_weight_artifact_extensions(tmp_path: Path, ext: str) -> None:
    repo_root = _REPO_ROOT

    shadow_root = "KT_PROD_CLEANROOM/exports/adapters_shadow/_tests"
    promoted_root = "KT_PROD_CLEANROOM/exports/adapters/_tests"
    job = _mk_jobspec(export_shadow_root=shadow_root, export_promoted_root=promoted_root)
    job_dir = (repo_root / shadow_root / job["job_id"]).resolve()
    if job_dir.exists():
        shutil.rmtree(job_dir)

    job_path = tmp_path / "job.json"
    contract_path = tmp_path / "contract.json"
    budget_path = tmp_path / "budget.json"

    run_job_rel = "KT_PROD_CLEANROOM/tools/training/fl3_factory/run_job.py"
    ep = {
        "run_job": {"path": run_job_rel, "sha256": sha256_file_normalized(repo_root / run_job_rel)},
        "harvest": {
            "path": "KT_PROD_CLEANROOM/tools/training/fl3_factory/harvest.py",
            "sha256": sha256_file_normalized(repo_root / "KT_PROD_CLEANROOM/tools/training/fl3_factory/harvest.py"),
        },
    }
    _write_json(job_path, job)
    _write_json(contract_path, _mk_contract(repo_root=repo_root, entrypoints=ep))
    _write_json(
        budget_path,
        {
            "schema_id": "kt.global_budget_state.v1",
            "schema_version_hash": schema_version_hash("fl3/kt.global_budget_state.v1.json"),
            "day_utc": "2026-01-01",
            "gpu_hours_used": 0.0,
            "jobs_run": 0,
            "lock_state": "OPEN",
            "last_t1_failure": None,
        },
    )

    try:
        assert int(run_job_main(["--job", str(job_path), "--organ-contract", str(contract_path), "--budget-state", str(budget_path)])) == EXIT_OK

        # Add a forbidden weight-like artifact and ensure meta-evaluator fails closed.
        (job_dir / f"forbidden{ext}").write_bytes(b"not really weights\n")

        with pytest.raises(FL3ValidationError):
            verify_job_dir(repo_root=repo_root, job_dir=job_dir)
    finally:
        if job_dir.exists():
            shutil.rmtree(job_dir)

