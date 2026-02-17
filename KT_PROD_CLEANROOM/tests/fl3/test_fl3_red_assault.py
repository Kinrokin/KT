from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.schema_registry import validate_object_with_binding  # noqa: E402
from tools.verification.fl3_red_assault import run_red_assault  # noqa: E402


def test_fl3_factory_red_assault_fail_closed() -> None:
    # Ensure the red assault export roots are clean; this drill uses WORM receipts and must not
    # depend on prior local state under KT_PROD_CLEANROOM/exports/.
    export_shadow_root = (_REPO_ROOT / "KT_PROD_CLEANROOM" / "exports" / "adapters_shadow" / "_red_assault").resolve()
    export_promoted_root = (_REPO_ROOT / "KT_PROD_CLEANROOM" / "exports" / "adapters" / "_red_assault").resolve()
    for root in (export_shadow_root, export_promoted_root):
        if root.exists():
            shutil.rmtree(root)

    with tempfile.TemporaryDirectory() as td:
        report = run_red_assault(tmp_dir=Path(td))
    validate_object_with_binding(report)
    assert report["schema_id"] == "kt.fl3.red_assault.v1"
    assert report["all_passed"] is True
