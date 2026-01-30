from __future__ import annotations

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_ = bootstrap_syspath()

from tools.verification.fl3_meta_evaluator import main  # noqa: E402


def test_fl3_meta_evaluator_law_passes() -> None:
    assert main([]) == 0

