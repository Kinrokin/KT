from __future__ import annotations

import json
import shutil
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from tools.training.fl3_factory.hashing import sha256_file_normalized  # noqa: E402
from tools.training.fl3_factory.run_job import EXIT_OK, main  # noqa: E402
from tools.verification.fl3_canonical import sha256_json  # noqa: E402
from tools.verification.fl3_meta_evaluator import verify_job_dir  # noqa: E402
from tools.verification.fl3_validators import FL3ValidationError  # noqa: E402
from schemas.schema_files import schema_version_hash  # noqa: E402


def _write_json(p: Path, obj: dict) -> None:
    p.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _mk_jobspec(*, export_shadow_root: str, export_promoted_root: str) -> dict:
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
        "seed": 42,
        "export_shadow_root": export_shadow_root,
        "export_promoted_root": export_promoted_root,
    }
    job["job_id"] = sha256_json({k: v for k, v in job.items() if k != "job_id"})
    return job


def _mk_contract(*, entrypoints: dict) -> dict:
    c = {
        "schema_id": "kt.factory.organ_contract.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.organ_contract.v1.json"),
        "contract_id": "",
        "entrypoints": entrypoints,
        "allowed_base_models": ["mistral-7b"],
        "allowed_training_modes": ["head_only", "lora"],
        "allowed_output_schemas": sorted(
            [
                "kt.factory.dataset.v1",
                "kt.factory.eval_report.v1",
                "kt.factory.eval_report.v2",
                "kt.factory.judgement.v1",
                "kt.factory.jobspec.v1",
                "kt.factory.promotion.v1",
                "kt.factory.train_manifest.v1",
                "kt.policy_bundle.v1",
                "kt.reasoning_trace.v1",
                "kt.signal_quality.v1",
                "kt.factory.phase_trace.v1",
                "kt.hash_manifest.v1",
                "kt.factory.job_dir_manifest.v1",
                "kt.immune_snapshot.v1",
                "kt.epigenetic_summary.v1",
                "kt.fitness_region.v1",
                "kt.shadow_adapter_manifest.v1",
            ]
        ),
        "allowed_export_roots": [
            "KT_PROD_CLEANROOM/exports/adapters",
            "KT_PROD_CLEANROOM/exports/adapters_shadow",
        ],
        "created_at": "2026-01-01T00:00:00Z",
    }
    c["contract_id"] = sha256_json({k: v for k, v in c.items() if k not in {"created_at", "contract_id"}})
    return c


def test_factory_outputs_do_not_emit_runtime_srr_air(tmp_path: Path) -> None:
    repo_root = _REPO_ROOT

    shadow_root = "KT_PROD_CLEANROOM/exports/adapters_shadow/_tests"
    promoted_root = "KT_PROD_CLEANROOM/exports/adapters/_tests"

    job = _mk_jobspec(export_shadow_root=shadow_root, export_promoted_root=promoted_root)
    out_dir = (repo_root / shadow_root / job["job_id"]).resolve()
    if out_dir.exists():
        shutil.rmtree(out_dir)

    job_path = tmp_path / "job.json"
    contract_path = tmp_path / "contract.json"
    budget_path = tmp_path / "budget.json"

    run_job_rel = "KT_PROD_CLEANROOM/tools/training/fl3_factory/run_job.py"
    ep = {"run_job": {"path": run_job_rel, "sha256": sha256_file_normalized(repo_root / run_job_rel)}}

    _write_json(job_path, job)
    _write_json(contract_path, _mk_contract(entrypoints=ep))
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
        rc = main(["--job", str(job_path), "--organ-contract", str(contract_path), "--budget-state", str(budget_path)])
        assert rc == EXIT_OK

        verify_job_dir(repo_root=repo_root, job_dir=out_dir)
    finally:
        if out_dir.exists():
            shutil.rmtree(out_dir)


def test_meta_evaluator_rejects_forged_runtime_receipt_in_job_dir(tmp_path: Path) -> None:
    repo_root = _REPO_ROOT
    job_dir = tmp_path / "jobdir"
    job_dir.mkdir(parents=True)

    # Minimal required files for verify_job_dir() shape (we don't need them schema-valid for this test;
    # we just need the forbidden SRR artifact to be detected fail-closed first).
    (job_dir / "job.json").write_text("{}", encoding="utf-8")
    (job_dir / "signal_quality.json").write_text("{}", encoding="utf-8")
    (job_dir / "immune_snapshot.json").write_text("{}", encoding="utf-8")
    (job_dir / "epigenetic_summary.json").write_text("{}", encoding="utf-8")
    (job_dir / "fitness_region.json").write_text("{}", encoding="utf-8")

    (job_dir / "forged_srr.json").write_text(json.dumps({"schema_id": "kt.routing_record.v1"}), encoding="utf-8")

    try:
        verify_job_dir(repo_root=repo_root, job_dir=job_dir)
        raise AssertionError("Expected verify_job_dir to fail-closed on forged SRR schema_id")
    except FL3ValidationError as exc:
        assert "forbidden runtime receipt schema_id" in str(exc)
