from __future__ import annotations

import json
import shutil
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.schema_files import schema_version_hash  # noqa: E402
from tools.training.fl3_factory.hashing import sha256_file_normalized  # noqa: E402
from tools.training.fl3_factory.run_job import EXIT_OK, main as run_job_main  # noqa: E402
from tools.verification.fl3_canonical import sha256_json  # noqa: E402


def _write_json(p: Path, obj: dict) -> None:
    p.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _mk_jobspec(*, export_shadow_root: str, export_promoted_root: str, seed: int, role: str) -> dict:
    job = {
        "schema_id": "kt.factory.jobspec.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.jobspec.v1.json"),
        "job_id": "",
        "adapter_id": "fl4.metabolism.proof.v1",
        "adapter_version": "1",
        "role": role,
        "mode": "SMOKE",
        "run_kind": "STANDARD",
        "base_model_id": "mistral-7b",
        "training_mode": "head_only",
        "seed": seed,
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
        "allowed_training_modes": ["head_only"],
        "allowed_output_schemas": sorted(
            [
                "kt.factory.dataset.v1",
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


def _load_root_hash(job_dir: Path) -> str:
    hm = json.loads((job_dir / "hash_manifest.json").read_text(encoding="utf-8"))
    return str(hm.get("root_hash"))


def test_fl4_metabolism_perturbations_change_hash_root(tmp_path: Path) -> None:
    repo_root = _REPO_ROOT

    shadow_root = "KT_PROD_CLEANROOM/exports/adapters_shadow/_tests"
    promoted_root = "KT_PROD_CLEANROOM/exports/adapters/_tests"

    base = _mk_jobspec(export_shadow_root=shadow_root, export_promoted_root=promoted_root, seed=42, role="ARCHITECT")
    pert = _mk_jobspec(export_shadow_root=shadow_root, export_promoted_root=promoted_root, seed=43, role="ARCHITECT")

    base_dir = (repo_root / shadow_root / base["job_id"]).resolve()
    pert_dir = (repo_root / shadow_root / pert["job_id"]).resolve()
    for d in (base_dir, pert_dir):
        if d.exists():
            shutil.rmtree(d)

    job_base_path = tmp_path / "job_base.json"
    job_pert_path = tmp_path / "job_pert.json"
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

    _write_json(job_base_path, base)
    _write_json(job_pert_path, pert)
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
        rc = run_job_main(["--job", str(job_base_path), "--organ-contract", str(contract_path), "--budget-state", str(budget_path)])
        assert rc == EXIT_OK
        rc = run_job_main(["--job", str(job_pert_path), "--organ-contract", str(contract_path), "--budget-state", str(budget_path)])
        assert rc == EXIT_OK

        root1 = _load_root_hash(base_dir)
        root2 = _load_root_hash(pert_dir)
        assert root1 != root2
    finally:
        for d in (base_dir, pert_dir):
            if d.exists():
                shutil.rmtree(d)

