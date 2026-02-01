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
from tools.verification.fl3_validators import load_fl3_canonical_runtime_paths, validate_schema_bound_object  # noqa: E402
from tools.verification.fl4_determinism_canary import main as canary_main  # noqa: E402
from tools.verification.fl4_promote import main as promote_main  # noqa: E402


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
        "adapter_id": "lobe.architect.v1",
        "adapter_version": "999",
        "role": "ARCHITECT",
        "mode": "SOVEREIGN",
        "run_kind": "STANDARD",
        "base_model_id": "mistral-7b",
        "training_mode": "head_only",
        "seed": 42,
        "export_shadow_root": export_shadow_root,
        "export_promoted_root": export_promoted_root,
    }
    job["job_id"] = sha256_json({k: v for k, v in job.items() if k != "job_id"})
    return job


def test_fl4_atomic_promotion_creates_promoted_package_and_updates_index(tmp_path: Path) -> None:
    repo_root = _REPO_ROOT
    paths = load_fl3_canonical_runtime_paths(repo_root=repo_root)

    shadow_root = "KT_PROD_CLEANROOM/exports/adapters_shadow/_tests_fl4_promote"
    promoted_root = "KT_PROD_CLEANROOM/exports/adapters/_tests_fl4_promote"

    job = _mk_jobspec(export_shadow_root=shadow_root, export_promoted_root=promoted_root)
    job_dir = (repo_root / shadow_root / job["job_id"]).resolve()

    job_path = tmp_path / "job.json"
    contract_path = tmp_path / "contract.json"
    budget_path = tmp_path / "budget.json"
    canary_path = tmp_path / "canary.json"
    report_path = tmp_path / "promotion_report.json"

    _write_json(job_path, job)
    _write_json(contract_path, _mk_contract(repo_root=repo_root))
    _write_json(budget_path, _mk_budget())

    # Ensure clean slate.
    if job_dir.exists():
        shutil.rmtree(job_dir)

    # Capture existing promoted index (if any) so we can restore it.
    promoted_index_path = (repo_root / str(paths["exports_adapters_root"]) / "promoted_index.json").resolve()
    promoted_index_backup = promoted_index_path.read_text(encoding="utf-8") if promoted_index_path.exists() else ""
    promoted_adapter_root = (repo_root / str(paths["exports_adapters_root"]) / job["adapter_id"] / job["adapter_version"]).resolve()
    if promoted_adapter_root.exists():
        shutil.rmtree(promoted_adapter_root)

    try:
        rc = int(run_job_main(["--job", str(job_path), "--organ-contract", str(contract_path), "--budget-state", str(budget_path)]))
        assert rc == EXIT_OK
        assert job_dir.exists()

        promotion = json.loads((job_dir / "promotion.json").read_text(encoding="utf-8"))
        assert promotion.get("schema_id") == "kt.factory.promotion.v1"
        # In canonical FL4 lane, SOVEREIGN + PASS should be eligible to promote.
        assert promotion.get("decision") == "PROMOTE"

        # Determinism canary must PASS to allow promotion.
        rc_canary = int(
            canary_main(
                [
                    "--organ-contract",
                    str(contract_path),
                    "--budget-state",
                    str(budget_path),
                    "--out",
                    str(canary_path),
                ]
            )
        )
        assert rc_canary == 0
        canary = json.loads(canary_path.read_text(encoding="utf-8"))
        validate_schema_bound_object(canary)
        assert canary.get("schema_id") == "kt.canary_artifact.v1"
        assert canary.get("canary_result") == "PASS"

        # Promote atomically.
        rc_promote = int(
            promote_main(
                [
                    "--job-dir",
                    str(job_dir),
                    "--canary-artifact",
                    str(canary_path),
                    "--out",
                    str(report_path),
                ]
            )
        )
        assert rc_promote == 0

        report = json.loads(report_path.read_text(encoding="utf-8"))
        promoted_dir = (repo_root / report["promoted_dir"]).resolve()
        assert promoted_dir.exists()

        promoted_manifest = json.loads((promoted_dir / "promoted_manifest.json").read_text(encoding="utf-8"))
        validate_schema_bound_object(promoted_manifest)
        assert promoted_manifest.get("schema_id") == "kt.promoted_manifest.v1"
        assert promoted_manifest.get("content_hash") == report.get("content_hash")

        # Promotion isolation: promoted package must verify even if the source job_dir is deleted.
        shutil.rmtree(job_dir)
        assert not job_dir.exists()
        from tools.verification.fl3_meta_evaluator import verify_job_dir  # noqa: E402

        verify_job_dir(repo_root=repo_root, job_dir=promoted_dir)

        assert promoted_index_path.exists()
        idx = json.loads(promoted_index_path.read_text(encoding="utf-8"))
        validate_schema_bound_object(idx)
        assert idx.get("schema_id") == "kt.promoted_index.v1"
        entries = idx.get("entries")
        assert isinstance(entries, list)
        assert any(
            isinstance(e, dict)
            and e.get("adapter_id") == job["adapter_id"]
            and e.get("adapter_version") == job["adapter_version"]
            and e.get("content_hash") == report.get("content_hash")
            for e in entries
        )
    finally:
        # Cleanup job_dir and canary staging.
        if job_dir.exists():
            shutil.rmtree(job_dir)
        canary_exports = (repo_root / str(paths["exports_shadow_root"]) / "_canary").resolve()
        if canary_exports.exists():
            shutil.rmtree(canary_exports)
        canary_runs = (repo_root / "KT_PROD_CLEANROOM" / "exports" / "adapters_shadow" / "_runs" / "FL4_CANARY").resolve()
        if canary_runs.exists():
            shutil.rmtree(canary_runs)

        # Cleanup promoted artifacts; restore prior promoted_index if it existed.
        if report_path.exists():
            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
                pd = (repo_root / str(report.get("promoted_dir", ""))).resolve()
                if pd.exists():
                    shutil.rmtree(pd)
            except Exception:
                pass
        if promoted_adapter_root.exists():
            shutil.rmtree(promoted_adapter_root)
        if promoted_index_backup:
            promoted_index_path.parent.mkdir(parents=True, exist_ok=True)
            promoted_index_path.write_text(promoted_index_backup, encoding="utf-8")
        else:
            if promoted_index_path.exists():
                promoted_index_path.unlink()
