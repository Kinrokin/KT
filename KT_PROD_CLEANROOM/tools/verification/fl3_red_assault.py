from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

from tools.verification.fl3_canonical import repo_root_from, sha256_json


@dataclass(frozen=True)
class AttackResult:
    attack_id: str
    expected_exit_codes: Tuple[int, ...]
    observed_exit_code: int

    @property
    def passed(self) -> bool:
        return self.observed_exit_code in self.expected_exit_codes


def _mk_base_jobspec() -> Dict[str, Any]:
    from schemas.schema_files import schema_version_hash  # type: ignore

    job = {
        "schema_id": "kt.factory.jobspec.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.jobspec.v1.json"),
        "job_id": "",
        "adapter_id": "lobe.red_assault_probe.v1",
        "adapter_version": "1",
        "role": "AUDITOR",
        "mode": "SMOKE",
        "run_kind": "STANDARD",
        "base_model_id": "mistral-7b",
        "training_mode": "head_only",
        "seed": 42,
        "export_shadow_root": "KT_PROD_CLEANROOM/exports/adapters_shadow/_red_assault",
        "export_promoted_root": "KT_PROD_CLEANROOM/exports/adapters/_red_assault",
    }
    job["job_id"] = sha256_json({k: v for k, v in job.items() if k != "job_id"})
    return job


def _mk_min_contract(repo_root: Path) -> Dict[str, Any]:
    from schemas.schema_files import schema_version_hash  # type: ignore

    from tools.training.fl3_factory.hashing import sha256_file_normalized

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
                "kt.factory.jobspec.v1",
                "kt.factory.dataset.v1",
                "kt.reasoning_trace.v1",
                "kt.factory.judgement.v1",
                "kt.factory.train_manifest.v1",
                "kt.factory.eval_report.v1",
                "kt.signal_quality.v1",
                "kt.immune_snapshot.v1",
                "kt.epigenetic_summary.v1",
                "kt.fitness_region.v1",
                "kt.factory.promotion.v1",
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


def _run_job(job: Dict[str, Any], contract: Dict[str, Any], *, tmp_dir: Path) -> int:
    from tools.training.fl3_factory.run_job import main

    job_path = tmp_dir / "job.json"
    contract_path = tmp_dir / "contract.json"
    budget_path = tmp_dir / "budget.json"

    job_path.write_text(json.dumps(job, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
    contract_path.write_text(json.dumps(contract, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
    budget_path.write_text(
        json.dumps(
            {
                "schema_id": "kt.global_budget_state.v1",
                "schema_version_hash": job["schema_version_hash"],  # placeholder; validated by schema binding below
                "day_utc": "2026-01-01",
                "gpu_hours_used": 0.0,
                "jobs_run": 0,
                "lock_state": "OPEN",
                "last_t1_failure": None,
            },
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
        )
        + "\n",
        encoding="utf-8",
    )

    # Patch budget schema hash to real value.
    from schemas.schema_files import schema_version_hash  # type: ignore

    budget_obj = json.loads(budget_path.read_text(encoding="utf-8"))
    budget_obj["schema_version_hash"] = schema_version_hash("fl3/kt.global_budget_state.v1.json")
    budget_path.write_text(json.dumps(budget_obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")

    return int(main(["--job", str(job_path), "--organ-contract", str(contract_path), "--budget-state", str(budget_path)]))


def run_red_assault(*, tmp_dir: Path) -> Dict[str, Any]:
    repo_root = repo_root_from(Path(__file__))
    base_job = _mk_base_jobspec()
    contract = _mk_min_contract(repo_root)

    results: List[AttackResult] = []

    # Baseline must pass (sanity check).
    rc_ok = _run_job(base_job, contract, tmp_dir=tmp_dir)
    results.append(AttackResult("BASELINE_SMOKE", (0,), rc_ok))

    # RA1: export root traversal / escape attempt in jobspec.
    job_bad_path = dict(base_job)
    job_bad_path["export_shadow_root"] = "KT_PROD_CLEANROOM/exports/../../escape"
    job_bad_path["job_id"] = sha256_json({k: v for k, v in job_bad_path.items() if k != "job_id"})
    rc = _run_job(job_bad_path, contract, tmp_dir=tmp_dir)
    results.append(AttackResult("RA1_EXPORT_ROOT_ESCAPE", (2,), rc))

    # RA2: schema_version_hash tamper.
    job_bad_schema = dict(base_job)
    job_bad_schema["schema_version_hash"] = "0" * 64
    job_bad_schema["job_id"] = sha256_json({k: v for k, v in job_bad_schema.items() if k != "job_id"})
    rc = _run_job(job_bad_schema, contract, tmp_dir=tmp_dir)
    results.append(AttackResult("RA2_SCHEMA_HASH_TAMPER", (2,), rc))

    # RA3: organ contract entrypoint hash tamper.
    contract_bad = json.loads(json.dumps(contract))
    contract_bad["entrypoints"]["run_job"]["sha256"] = "0" * 64
    rc = _run_job(base_job, contract_bad, tmp_dir=tmp_dir)
    results.append(AttackResult("RA3_ENTRYPOINT_HASH_TAMPER", (2,), rc))

    return {
        "schema_id": "kt.fl3.red_assault.v1",
        "results": [
            {
                "attack_id": r.attack_id,
                "expected_exit_codes": list(r.expected_exit_codes),
                "observed_exit_code": r.observed_exit_code,
                "passed": r.passed,
            }
            for r in results
        ],
        "all_passed": all(r.passed for r in results),
    }


def main(argv: List[str] | None = None) -> int:
    import argparse
    import tempfile

    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None, help="Optional output JSON report path")
    args = ap.parse_args(argv)

    with tempfile.TemporaryDirectory() as td:
        report = run_red_assault(tmp_dir=Path(td))
    out = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True)
    if args.out:
        Path(args.out).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    return 0 if report.get("all_passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
