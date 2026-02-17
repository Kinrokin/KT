from __future__ import annotations

import json
import shutil
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.schema_files import schema_version_hash  # noqa: E402
from tools.training.fl3_factory.hashing import sha256_file_normalized  # noqa: E402
from tools.training.fl3_factory.run_job import EXIT_CONTRACT, EXIT_OK, main as run_job_main  # noqa: E402
from tools.verification.fl3_canonical import sha256_json  # noqa: E402
from tools.verification.fl3_validators import load_fl3_canonical_runtime_paths, validate_schema_bound_object  # noqa: E402


def _write_json(p: Path, obj: dict) -> None:
    p.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")


def _mk_contract(*, repo_root: Path) -> dict:
    run_job_rel = "KT_PROD_CLEANROOM/tools/training/fl3_factory/run_job.py"
    harvest_rel = "KT_PROD_CLEANROOM/tools/training/fl3_factory/harvest.py"
    ep = {
        "run_job": {"path": run_job_rel, "sha256": sha256_file_normalized(repo_root / run_job_rel)},
        "harvest": {"path": harvest_rel, "sha256": sha256_file_normalized(repo_root / harvest_rel)},
    }
    c = {
        "schema_id": "kt.factory.organ_contract.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.organ_contract.v1.json"),
        "contract_id": "",
        "entrypoints": ep,
        "allowed_base_models": ["mistral-7b"],
        "allowed_training_modes": ["head_only"],
        "allowed_output_schemas": sorted(
            [
                "kt.factory.jobspec.v1",
                "kt.training_admission_receipt.v1",
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


def _mk_budget() -> dict:
    return {
        "schema_id": "kt.global_budget_state.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.global_budget_state.v1.json"),
        "day_utc": "2026-01-01",
        "gpu_hours_used": 0.0,
        "jobs_run": 0,
        "lock_state": "OPEN",
        "last_t1_failure": None,
    }


def _mk_jobspec(*, export_shadow_root: str, export_promoted_root: str) -> dict:
    job = {
        "schema_id": "kt.factory.jobspec.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.jobspec.v1.json"),
        "job_id": "",
        "adapter_id": "epic29.worm.adapter.v1",
        "adapter_version": "0",
        "role": "TEST",
        "mode": "SMOKE",
        "run_kind": "STANDARD",
        "base_model_id": "mistral-7b",
        "training_mode": "head_only",
        "seed": 0,
        "export_shadow_root": export_shadow_root,
        "export_promoted_root": export_promoted_root,
    }
    job["job_id"] = sha256_json({k: v for k, v in job.items() if k != "job_id"})
    validate_schema_bound_object(job)
    return job


def test_epic29_factory_worm_refuses_overwrite_on_tamper(tmp_path: Path) -> None:
    repo_root = _REPO_ROOT
    _ = load_fl3_canonical_runtime_paths(repo_root=repo_root)

    shadow_root = "KT_PROD_CLEANROOM/exports/adapters_shadow/_tests_epic29_worm"
    promoted_root = "KT_PROD_CLEANROOM/exports/adapters/_tests_epic29_worm"
    job = _mk_jobspec(export_shadow_root=shadow_root, export_promoted_root=promoted_root)

    job_dir = (repo_root / shadow_root / job["job_id"]).resolve()

    job_path = tmp_path / "job.json"
    contract_path = tmp_path / "contract.json"
    budget_path = tmp_path / "budget.json"

    _write_json(job_path, job)
    _write_json(contract_path, _mk_contract(repo_root=repo_root))
    _write_json(budget_path, _mk_budget())

    # Ensure a clean slate for the deterministic rerun test.
    if job_dir.exists():
        shutil.rmtree(job_dir)

    try:
        assert int(run_job_main(["--job", str(job_path), "--organ-contract", str(contract_path), "--budget-state", str(budget_path)])) == EXIT_OK
        assert (job_dir / "dataset.json").exists()

        # Tamper with a WORM-governed schema object; rerun must fail closed (refuse overwrite).
        dataset_path = job_dir / "dataset.json"
        dataset_path.write_text(dataset_path.read_text(encoding="utf-8") + " ", encoding="utf-8", newline="\n")

        assert (
            int(run_job_main(["--job", str(job_path), "--organ-contract", str(contract_path), "--budget-state", str(budget_path)]))
            == EXIT_CONTRACT
        )
    finally:
        # Tests may clean up exports; this is not a production lane.
        if job_dir.exists():
            shutil.rmtree(job_dir)

