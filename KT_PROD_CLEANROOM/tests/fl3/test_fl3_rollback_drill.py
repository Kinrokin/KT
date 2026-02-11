from __future__ import annotations

import json
import tempfile
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

repo_root = bootstrap_syspath()

from tools.verification.fl3_rollback_drill import run_rollback_drill  # noqa: E402


def test_fl3_rollback_drill_restores_registry_bytes() -> None:
    paths = json.loads((repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "FL3_CANONICAL_RUNTIME_PATHS.json").read_text(encoding="utf-8"))
    registry_rel = paths["runtime_registry_path"]
    registry_path = (repo_root / registry_rel).resolve()
    assert registry_path.exists()

    with tempfile.TemporaryDirectory() as td:
        report = run_rollback_drill(registry_path=registry_path, work_dir=Path(td))
    assert report["restored_matches_original"] is True

