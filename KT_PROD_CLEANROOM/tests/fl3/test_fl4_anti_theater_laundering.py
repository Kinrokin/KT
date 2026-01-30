from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.schema_files import schema_version_hash  # noqa: E402
from tools.training.fl3_factory.hashing import sha256_file_normalized  # noqa: E402
from tools.training.fl3_factory.manifests import write_manifests_for_job_dir  # noqa: E402
from tools.training.fl3_factory.run_job import EXIT_OK, main as run_job_main  # noqa: E402
from tools.verification.fl3_canonical import sha256_json  # noqa: E402
from tools.verification.fl3_meta_evaluator import verify_job_dir  # noqa: E402
from tools.verification.fl3_validators import FL3ValidationError  # noqa: E402


def _write_json(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _mk_contract(*, repo_root: Path) -> dict:
    run_job_rel = "KT_PROD_CLEANROOM/tools/training/fl3_factory/run_job.py"
    ep = {"run_job": {"path": run_job_rel, "sha256": sha256_file_normalized(repo_root / run_job_rel)}}
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
        "adapter_id": "lobe.critic.v1",
        "adapter_version": "1",
        "role": "CRITIC",
        "mode": "SMOKE",
        "run_kind": "STANDARD",
        "base_model_id": "mistral-7b",
        "training_mode": "head_only",
        "seed": 7,
        "export_shadow_root": export_shadow_root,
        "export_promoted_root": export_promoted_root,
    }
    job["job_id"] = sha256_json({k: v for k, v in job.items() if k != "job_id"})
    return job


def test_fl4_anti_theater_detects_metric_laundering_even_if_manifests_match(tmp_path: Path) -> None:
    repo_root = _REPO_ROOT
    shadow_root = "KT_PROD_CLEANROOM/exports/adapters_shadow/_tests_fl4_launder"
    promoted_root = "KT_PROD_CLEANROOM/exports/adapters/_tests_fl4_launder"

    job = _mk_jobspec(export_shadow_root=shadow_root, export_promoted_root=promoted_root)
    job_dir = (repo_root / shadow_root / job["job_id"]).resolve()

    job_path = tmp_path / "job.json"
    contract_path = tmp_path / "contract.json"
    budget_path = tmp_path / "budget.json"

    _write_json(job_path, job)
    _write_json(contract_path, _mk_contract(repo_root=repo_root))
    _write_json(budget_path, _mk_budget())

    if job_dir.exists():
        shutil.rmtree(job_dir)

    try:
        rc = int(run_job_main(["--job", str(job_path), "--organ-contract", str(contract_path), "--budget-state", str(budget_path)]))
        assert rc == EXIT_OK
        assert job_dir.exists()

        # Baseline: verifier passes.
        verify_job_dir(repo_root=repo_root, job_dir=job_dir)

        # Launder attempt: tamper eval_report.json metric while keeping filesystem hashes consistent
        # by regenerating hash_manifest + job_dir_manifest.
        eval_path = job_dir / "eval_report.json"
        eval_obj = json.loads(eval_path.read_text(encoding="utf-8"))
        assert eval_obj.get("schema_id") == "kt.factory.eval_report.v2"
        # Make the metric wrong while keeping types correct.
        eval_obj["utility_floor_score"] = float(eval_obj.get("utility_floor_score", 0.0)) + 0.123
        eval_path.write_text(json.dumps(eval_obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")

        required_relpaths = [
            "job.json",
            "dataset.json",
            "reasoning_trace.json",
            "judgement.json",
            "train_manifest.json",
            "hypotheses/policy_bundles.jsonl",
            "eval_report.json",
            "signal_quality.json",
            "immune_snapshot.json",
            "epigenetic_summary.json",
            "fitness_region.json",
            "phase_trace.json",
            "promotion.json",
        ]
        # Regenerate manifests to match the tampered file (laundering file-hash checks).
        write_manifests_for_job_dir(job_dir=job_dir, job_id=str(job["job_id"]), parent_hash="0" * 64, required_relpaths=required_relpaths)

        # Verifier must still fail closed because it recomputes the metric from the policy bundles + utility pack.
        with pytest.raises(FL3ValidationError, match=r"utility_floor_score"):
            verify_job_dir(repo_root=repo_root, job_dir=job_dir)
    finally:
        if job_dir.exists():
            shutil.rmtree(job_dir)

