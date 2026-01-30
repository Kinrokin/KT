from __future__ import annotations

import json
import multiprocessing as mp
import os
import time
from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.schema_files import schema_version_hash  # noqa: E402
from tools.training.fl3_factory.budget import budget_state_payload_hash, record_t1_failure  # noqa: E402
from tools.training.fl3_factory.hashing import sha256_file_normalized  # noqa: E402
from tools.training.fl3_factory.lockfile import exclusive_lock  # noqa: E402
from tools.training.fl3_factory.run_job import EXIT_BUDGET, EXIT_OK, main  # noqa: E402
from tools.verification.fl3_canonical import sha256_json  # noqa: E402


def _write_json(p: Path, obj: dict) -> None:
    p.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _hold_lock(lock_path: str, hold_s: float) -> None:
    with exclusive_lock(Path(lock_path), timeout_s=2.0):
        time.sleep(hold_s)


def test_fl3_budget_lock_contention(tmp_path: Path) -> None:
    lock_path = tmp_path / "x.lock"
    p = mp.Process(target=_hold_lock, args=(str(lock_path), 0.75))
    p.start()
    try:
        # Wait until the child has created the lock file (fail-closed if it never appears).
        deadline = time.time() + 1.0
        while not lock_path.exists() and time.time() < deadline:
            time.sleep(0.01)
        assert lock_path.exists()
        with pytest.raises(Exception):
            with exclusive_lock(lock_path, timeout_s=0.1):
                pass
    finally:
        p.join(timeout=2.0)
        if p.is_alive():
            p.terminate()


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
        "seed": 42,
        "export_shadow_root": "KT_PROD_CLEANROOM/exports/adapters_shadow/_tests",
        "export_promoted_root": "KT_PROD_CLEANROOM/exports/adapters/_tests",
    }
    job["job_id"] = sha256_json({k: v for k, v in job.items() if k != "job_id"})
    return job


def _mk_contract(repo_root: Path) -> dict:
    run_job_rel = "KT_PROD_CLEANROOM/tools/training/fl3_factory/run_job.py"
    ep = {
        "run_job": {"path": run_job_rel, "sha256": sha256_file_normalized(repo_root / run_job_rel)},
    }
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


def _mk_budget_state(*, locked: bool) -> dict:
    return {
        "schema_id": "kt.global_budget_state.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.global_budget_state.v1.json"),
        "day_utc": "2026-01-01",
        "gpu_hours_used": 0.0,
        "jobs_run": 0,
        "lock_state": "LOCKED" if locked else "OPEN",
        "last_t1_failure": "deadbeef" if locked else None,
    }


def _mk_signoff(*, key_id: str, payload_hash: str, secret: str) -> dict:
    import hmac, hashlib

    signoff = {
        "schema_id": "kt.human_signoff.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.human_signoff.v1.json"),
        "signoff_id": "",
        "key_id": key_id,
        "payload_hash": payload_hash,
        "hmac_signature": "",
        "created_at": "2026-01-01T00:00:00Z",
    }
    signoff["hmac_signature"] = hmac.new(secret.encode("utf-8"), payload_hash.encode("utf-8"), hashlib.sha256).hexdigest()
    signoff["signoff_id"] = sha256_json({k: v for k, v in signoff.items() if k not in {"created_at", "signoff_id"}})
    return signoff


def _mk_unlock(*, payload_hash: str, signoffs: list[dict]) -> dict:
    unlock = {
        "schema_id": "kt.global_unlock.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.global_unlock.v1.json"),
        "unlock_id": "",
        "payload_hash": payload_hash,
        "reason_codes": ["MANUAL_UNLOCK"],
        "signoffs": signoffs,
        "created_at": "2026-01-01T00:00:00Z",
    }
    unlock["unlock_id"] = sha256_json({k: v for k, v in unlock.items() if k not in {"created_at", "unlock_id"}})
    return unlock


def test_fl3_global_unlock_requires_artifact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo_root = _REPO_ROOT
    job = _mk_jobspec()
    contract = _mk_contract(repo_root)
    budget_locked = _mk_budget_state(locked=True)

    job_path = tmp_path / "job.json"
    contract_path = tmp_path / "contract.json"
    budget_path = tmp_path / "budget.json"
    unlock_path = tmp_path / "unlock.json"

    _write_json(job_path, job)
    _write_json(contract_path, contract)
    _write_json(budget_path, budget_locked)

    # Locked without unlock => fail closed.
    rc = main(["--job", str(job_path), "--organ-contract", str(contract_path), "--budget-state", str(budget_path)])
    assert rc == EXIT_BUDGET

    # Provide valid unlock with two distinct signoffs.
    payload_hash = budget_state_payload_hash(budget_locked)
    monkeypatch.setenv("KT_FL3_HMAC_KEY_alice", "secretA")
    monkeypatch.setenv("KT_FL3_HMAC_KEY_bob", "secretB")
    s1 = _mk_signoff(key_id="alice", payload_hash=payload_hash, secret="secretA")
    s2 = _mk_signoff(key_id="bob", payload_hash=payload_hash, secret="secretB")
    unlock = _mk_unlock(payload_hash=payload_hash, signoffs=[s1, s2])
    _write_json(unlock_path, unlock)

    rc2 = main(
        [
            "--job",
            str(job_path),
            "--organ-contract",
            str(contract_path),
            "--budget-state",
            str(budget_path),
            "--unlock-artifact",
            str(unlock_path),
        ]
    )
    assert rc2 == EXIT_OK


def test_fl3_t1_failure_locks_factory(tmp_path: Path) -> None:
    repo_root = _REPO_ROOT
    budget_path = tmp_path / "budget.json"
    _write_json(budget_path, _mk_budget_state(locked=False))
    locked = record_t1_failure(repo_root=repo_root, budget_state_path=budget_path, failure_id="f" * 64)
    assert locked["lock_state"] == "LOCKED"
