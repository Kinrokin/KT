from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from schemas.schema_files import schema_version_hash
from tools.training.fl3_factory.hashing import sha256_file_normalized
from tools.verification.fl3_canonical import repo_root_from, sha256_json
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object
from tools.verification.worm_write import write_text_worm


def build_min_organ_contract(*, repo_root: Path) -> Dict[str, Any]:
    """
    Deterministic minimal organ contract for canonical factory tooling.

    This mirrors the preflight FL4 minimal contract surface:
      - base_model_id: mistral-7b
      - training_mode: head_only
      - entrypoint: run_job.py with sha256_file_normalized
      - created_at is fixed epoch (not a hash input)
    """
    run_job_rel = "KT_PROD_CLEANROOM/tools/training/fl3_factory/run_job.py"
    ep = {"run_job": {"path": run_job_rel, "sha256": sha256_file_normalized(repo_root / run_job_rel)}}

    allowed_out: List[str] = sorted(
        [
            "kt.factory.jobspec.v1",
            # EPIC_15: master training admission valve.
            "kt.training_admission_receipt.v1",
            "kt.factory.dataset.v1",
            "kt.reasoning_trace.v1",
            "kt.factory.judgement.v1",
            "kt.factory.train_manifest.v1",
            # MRT-0 hypothesis generator output (schema-bound records in hypotheses/).
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
    )

    c: Dict[str, Any] = {
        "schema_id": "kt.factory.organ_contract.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.organ_contract.v1.json"),
        "contract_id": "",
        "entrypoints": ep,
        "allowed_base_models": ["mistral-7b"],
        "allowed_training_modes": ["head_only"],
        "allowed_output_schemas": allowed_out,
        "allowed_export_roots": [
            "KT_PROD_CLEANROOM/exports/adapters",
            "KT_PROD_CLEANROOM/exports/adapters_shadow",
        ],
        "created_at": "1970-01-01T00:00:00Z",
    }
    c["contract_id"] = sha256_json({k: v for k, v in c.items() if k not in {"created_at", "contract_id"}})
    validate_schema_bound_object(c)
    return c


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Write a deterministic minimal kt.factory.organ_contract.v1 JSON (WORM).")
    ap.add_argument("--out", required=True, help="Output path for organ contract JSON.")
    args = ap.parse_args(list(argv) if argv is not None else None)

    repo_root = repo_root_from(Path(__file__))
    out_path = Path(args.out).resolve()

    contract = build_min_organ_contract(repo_root=repo_root)
    write_text_worm(
        path=out_path,
        text=json.dumps(contract, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        label="organ_contract.json",
    )
    print(out_path.as_posix())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FL3ValidationError as exc:
        raise SystemExit(f"FAIL_CLOSED: {exc}") from exc

