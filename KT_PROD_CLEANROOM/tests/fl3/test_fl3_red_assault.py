from __future__ import annotations

import tempfile
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_ = bootstrap_syspath()

from tools.verification.fl3_red_assault import run_red_assault  # noqa: E402


def test_fl3_factory_red_assault_fail_closed() -> None:
    with tempfile.TemporaryDirectory() as td:
        report = run_red_assault(tmp_dir=Path(td))
    assert report["all_passed"] is True

