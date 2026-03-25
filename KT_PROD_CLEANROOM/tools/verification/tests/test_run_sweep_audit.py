from __future__ import annotations

from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

bootstrap_syspath()

from tools.verification.run_sweep_audit import RECEIPTS_DIR_REL, _pytest_cmd, _validate_receipts_cmd


def test_validate_receipts_command_includes_receipts_dir(tmp_path: Path) -> None:
    cmd = _validate_receipts_cmd(out_dir=tmp_path)

    assert cmd == [
        "python",
        "-m",
        "tools.verification.validate_receipts",
        "--receipts-dir",
        RECEIPTS_DIR_REL,
        "--out-dir",
        str(tmp_path),
    ]


def test_pytest_cmd_explicitly_loads_pytest_cov() -> None:
    cmd = _pytest_cmd("-q", "KT_PROD_CLEANROOM/tests")

    assert cmd == [
        "python",
        "-m",
        "pytest",
        "-p",
        "pytest_cov",
        "-q",
        "KT_PROD_CLEANROOM/tests",
    ]
