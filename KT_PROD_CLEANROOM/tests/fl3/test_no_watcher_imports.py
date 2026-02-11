from __future__ import annotations

from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from tools.verification.watcher_spc_validators import assert_no_watcher_imports_in_paths  # noqa: E402


@pytest.mark.parametrize(
    "rel",
    [
        "KT_PROD_CLEANROOM/tools/verification",
        "KT_PROD_CLEANROOM/tools/training",
        "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src",
    ],
)
def test_no_watcher_imports_in_canonical_modules(rel: str) -> None:
    root = _REPO_ROOT / Path(rel)
    assert_no_watcher_imports_in_paths(paths=[root])

