from __future__ import annotations

import json
from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.schema_files import schema_version_hash  # noqa: E402
from tools.training.fl3_factory.hashing import sha256_file_normalized  # noqa: E402
from tools.verification.fl3_canonical import sha256_json  # noqa: E402
from tools.verification.fl3_validators import FL3ValidationError  # noqa: E402
from tools.verification.derive_fl4_seal_artifacts import main as derive_main  # noqa: E402


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
        "allowed_output_schemas": [],
        "allowed_export_roots": [],
        "created_at": "1970-01-01T00:00:00Z",
    }
    c["contract_id"] = sha256_json({k: v for k, v in c.items() if k not in {"created_at", "contract_id"}})
    return c


def test_derive_fl4_seal_artifacts_refuses_ci_when_write_enabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    contract_path = tmp_path / "organ_contract.json"
    contract_path.write_text(
        json.dumps(_mk_contract(repo_root=_REPO_ROOT), indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("CI", "1")
    with pytest.raises(FL3ValidationError):
        _ = derive_main(["--organ-contract", str(contract_path), "--write", "--attestation-mode", "SIMULATED"])
