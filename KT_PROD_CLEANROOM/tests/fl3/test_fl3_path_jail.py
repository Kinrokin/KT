from __future__ import annotations

from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from tools.verification.fl3_canonical import repo_root_from  # noqa: E402
from tools.verification.fl3_validators import FL3ValidationError, assert_relpath_under_exports  # noqa: E402


def test_fl3_path_jail_accepts_shadow_subpaths() -> None:
    repo_root = repo_root_from(Path(__file__))
    p = assert_relpath_under_exports(
        repo_root=repo_root,
        relpath="KT_PROD_CLEANROOM/exports/adapters_shadow/_tests/x.json",
        allow_promoted=True,
    )
    assert str(p).endswith("KT_PROD_CLEANROOM\\exports\\adapters_shadow\\_tests\\x.json") or str(p).endswith(
        "KT_PROD_CLEANROOM/exports/adapters_shadow/_tests/x.json"
    )


def test_fl3_path_jail_rejects_traversal() -> None:
    repo_root = repo_root_from(Path(__file__))
    with pytest.raises(FL3ValidationError):
        _ = assert_relpath_under_exports(
            repo_root=repo_root,
            relpath="KT_PROD_CLEANROOM/exports/adapters_shadow/../AUDITS/x.json",
        )


def test_fl3_path_jail_rejects_absolute() -> None:
    repo_root = repo_root_from(Path(__file__))
    with pytest.raises(FL3ValidationError):
        _ = assert_relpath_under_exports(repo_root=repo_root, relpath=str((repo_root / "KT_PROD_CLEANROOM").resolve()))
