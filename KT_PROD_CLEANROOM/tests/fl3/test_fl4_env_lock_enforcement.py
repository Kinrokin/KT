from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = Path(bootstrap_syspath())

from tools.verification.preflight_fl4 import _enforce_env_lock  # noqa: E402


def test_env_lock_missing_required_emits_receipt_and_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Ensure one required key is missing.
    monkeypatch.delenv("PYTHONHASHSEED", raising=False)

    with pytest.raises(SystemExit):
        _enforce_env_lock(repo_root=_REPO_ROOT, env_for_subprocess=os.environ.copy(), out_dir=out_dir)

    receipt = out_dir / "env_mismatch_receipt.json"
    assert receipt.exists()
    obj = json.loads(receipt.read_text(encoding="utf-8"))
    assert obj.get("schema_id") == "kt.env_mismatch_receipt.v1"
    assert obj.get("reason") in {"required_key_missing", "required_key_mismatch", "undeclared_tracked_env", "forbidden_key_present", "forbidden_prefix_present"}

