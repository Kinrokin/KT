from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.schema_files import schema_version_hash  # noqa: E402
from tools.training.fl3_factory.hashing import sha256_file_normalized  # noqa: E402
from tools.training.fl3_factory.run_job import EXIT_OK, main  # noqa: E402
from tools.training.fl3_factory.tournament import (  # noqa: E402
    build_reveal_mapping,
    unseal_reveal_mapping,
)
from tools.verification.fl3_canonical import sha256_json  # noqa: E402
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object  # noqa: E402


def _write_json(p: Path, obj: dict) -> None:
    p.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def test_fl3_blind_pack_schema_rejects_identity_leak() -> None:
    bad = {
        "schema_id": "kt.blind_judgement_pack.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.blind_judgement_pack.v1.json"),
        "pack_id": "a" * 64,
        "job_id": "b" * 64,
        "items": [
            {
                "prompt_hash": "0" * 64,
                "candidate_hash": "1" * 64,
                "adapter_id": "leak",
            }
        ],
        "created_at": "2026-01-01T00:00:00Z",
    }
    with pytest.raises(FL3ValidationError):
        validate_schema_bound_object(bad)


def test_fl3_reveal_mapping_sealed_until_verdict(tmp_path: Path) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir(parents=True, exist_ok=True)

    sealed = build_reveal_mapping(
        job_id="0" * 64,
        mappings={"0" * 64: {"adapter_id": "a", "adapter_version": "1"}},
        sealed=True,
        verdict_ref=None,
    )
    validate_schema_bound_object(sealed)

    # Cannot unseal before verdict exists on disk.
    with pytest.raises(FL3ValidationError):
        _ = unseal_reveal_mapping(job_dir=job_dir, sealed_mapping=sealed, verdict_ref="judgement.json")

    # Create verdict file and unseal.
    (job_dir / "judgement.json").write_text("{}", encoding="utf-8")
    unsealed = unseal_reveal_mapping(job_dir=job_dir, sealed_mapping=sealed, verdict_ref="judgement.json")
    validate_schema_bound_object(unsealed)
    assert unsealed["sealed"] is False
    assert unsealed["verdict_ref"] == "judgement.json"


def _mk_jobspec(*, export_shadow_root: str, export_promoted_root: str) -> dict:
    job = {
        "schema_id": "kt.factory.jobspec.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.jobspec.v1.json"),
        "job_id": "",
        "adapter_id": "lobe.architect.v1",
        "adapter_version": "1",
        "role": "ARCHITECT",
        "mode": "SMOKE",
        "run_kind": "TOURNAMENT",
        "base_model_id": "mistral-7b",
        "training_mode": "head_only",
        "seed": 42,
        "export_shadow_root": export_shadow_root,
        "export_promoted_root": export_promoted_root,
        # Tournament entrants are added in a later commit; keep this job minimal for now.
    }
    job["job_id"] = sha256_json({k: v for k, v in job.items() if k != "job_id"})
    return job


def _mk_contract(*, repo_root: Path) -> dict:
    run_job_rel = "KT_PROD_CLEANROOM/tools/training/fl3_factory/run_job.py"
    ep = {"run_job": {"path": run_job_rel, "sha256": sha256_file_normalized(repo_root / run_job_rel)}}
    c = {
        "schema_id": "kt.factory.organ_contract.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.organ_contract.v1.json"),
        "contract_id": "",
        "entrypoints": ep,
        "allowed_base_models": ["mistral-7b"],
        "allowed_training_modes": ["head_only", "lora"],
        "allowed_output_schemas": sorted(
            [
                "kt.factory.dataset.v1",
                "kt.factory.eval_report.v1",
                "kt.factory.judgement.v1",
                "kt.factory.jobspec.v1",
                "kt.factory.promotion.v1",
                "kt.factory.train_manifest.v1",
                "kt.blind_judgement_pack.v1",
                "kt.reveal_mapping.v1",
                "kt.tournament_manifest.v1",
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


def test_fl3_factory_tournament_emits_blind_pack_and_mapping(tmp_path: Path) -> None:
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
    _write_json(job_path, job)
    _write_json(contract_path, _mk_contract(repo_root=repo_root))
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

        assert (out_dir / "blind_pack.json").exists()
        assert (out_dir / "reveal_mapping.sealed.json").exists()
        assert (out_dir / "reveal_mapping.json").exists()
        assert (out_dir / "tournament_manifest.json").exists()

        blind_pack = json.loads((out_dir / "blind_pack.json").read_text(encoding="utf-8"))
        validate_schema_bound_object(blind_pack)
        for item in blind_pack["items"]:
            assert sorted(item.keys()) == ["candidate_hash", "prompt_hash"]

        sealed = json.loads((out_dir / "reveal_mapping.sealed.json").read_text(encoding="utf-8"))
        validate_schema_bound_object(sealed)
        assert sealed["sealed"] is True
        assert sealed["verdict_ref"] is None

        unsealed = json.loads((out_dir / "reveal_mapping.json").read_text(encoding="utf-8"))
        validate_schema_bound_object(unsealed)
        assert unsealed["sealed"] is False
        assert unsealed["verdict_ref"] == "judgement.json"
    finally:
        if out_dir.exists():
            shutil.rmtree(out_dir)
