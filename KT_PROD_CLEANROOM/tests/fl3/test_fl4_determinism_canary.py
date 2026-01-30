from __future__ import annotations

import json
import shutil
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.schema_files import schema_version_hash  # noqa: E402
from tools.training.fl3_factory.hashing import sha256_file_normalized  # noqa: E402
from tools.verification.fl3_canonical import sha256_json  # noqa: E402
from tools.verification.fl3_validators import load_fl3_canonical_runtime_paths, validate_schema_bound_object  # noqa: E402
from tools.verification.fl4_determinism_canary import main as canary_main  # noqa: E402


def _write_json(p: Path, obj: dict) -> None:
    p.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _mk_contract(*, repo_root: Path) -> dict:
    run_job_rel = "KT_PROD_CLEANROOM/tools/training/fl3_factory/run_job.py"
    ep = {
        "run_job": {"path": run_job_rel, "sha256": sha256_file_normalized(repo_root / run_job_rel)},
        "harvest": {
            "path": "KT_PROD_CLEANROOM/tools/training/fl3_factory/harvest.py",
            "sha256": sha256_file_normalized(repo_root / "KT_PROD_CLEANROOM/tools/training/fl3_factory/harvest.py"),
        },
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


def test_fl4_determinism_canary_passes_and_emits_schema_bound_artifact(tmp_path: Path) -> None:
    repo_root = _REPO_ROOT

    contract_path = tmp_path / "organ_contract.json"
    budget_path = tmp_path / "budget.json"
    out_path = tmp_path / "canary_artifact.json"

    _write_json(contract_path, _mk_contract(repo_root=repo_root))
    _write_json(budget_path, _mk_budget())

    paths = load_fl3_canonical_runtime_paths(repo_root=repo_root)
    export_shadow_root = str(paths["exports_shadow_root"]).replace("\\", "/").rstrip("/") + "/_canary"

    try:
        rc = int(
            canary_main(
                [
                    "--organ-contract",
                    str(contract_path),
                    "--budget-state",
                    str(budget_path),
                    "--out",
                    str(out_path),
                ]
            )
        )
        assert rc == 0
        assert out_path.exists()

        obj = json.loads(out_path.read_text(encoding="utf-8"))
        validate_schema_bound_object(obj)
        assert obj.get("schema_id") == "kt.canary_artifact.v1"
        assert obj.get("canary_result") == "PASS"
        assert isinstance(obj.get("hash_manifest_root_hash"), str) and len(obj["hash_manifest_root_hash"]) == 64
    finally:
        # Clean up the canary job directory and its staging dir under exports.
        if out_path.exists():
            try:
                canary = json.loads(out_path.read_text(encoding="utf-8"))
                job_id = str(canary.get("canary_job_id", ""))
            except Exception:
                job_id = ""
            if job_id:
                out_dir = (repo_root / export_shadow_root / job_id).resolve()
                if out_dir.exists():
                    shutil.rmtree(out_dir)
        runs_dir = (repo_root / "KT_PROD_CLEANROOM" / "exports" / "adapters_shadow" / "_runs" / "FL4_CANARY").resolve()
        if runs_dir.exists():
            shutil.rmtree(runs_dir)

