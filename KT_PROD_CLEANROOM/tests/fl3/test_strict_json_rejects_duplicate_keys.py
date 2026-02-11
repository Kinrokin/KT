from __future__ import annotations

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from tools.verification.strict_json import DuplicateKeyError, loads_no_dupes  # noqa: E402


def test_strict_json_rejects_duplicate_keys() -> None:
    with pytest.raises(DuplicateKeyError):
        loads_no_dupes('{"a": 1, "a": 2}')
