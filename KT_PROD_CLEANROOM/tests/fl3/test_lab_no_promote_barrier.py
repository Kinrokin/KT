from __future__ import annotations

import json
from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from tools.verification.fl4_promote import FL3ValidationError, promote_job_dir  # noqa: E402


def test_lab_training_mode_cannot_promote_into_canonical_index(tmp_path: Path) -> None:
    job_dir = tmp_path / "job_dir"
    job_dir.mkdir(parents=True, exist_ok=True)
    (job_dir / "job.json").write_text(json.dumps({"training_mode": "lora"}) + "\n", encoding="utf-8", newline="\n")
    # Unused due to early fail-closed.
    canary = tmp_path / "canary.json"
    canary.write_text("{}", encoding="utf-8", newline="\n")

    with pytest.raises(FL3ValidationError):
        promote_job_dir(repo_root=_REPO_ROOT, job_dir=job_dir, canary_artifact_path=canary, out_report=None)

