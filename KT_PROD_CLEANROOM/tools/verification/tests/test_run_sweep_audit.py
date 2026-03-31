from __future__ import annotations

from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

bootstrap_syspath()

from tools.verification.run_sweep_audit import (
    RECEIPTS_DIR_REL,
    TEMPLE_PYTEST_TARGETS,
    VERIFICATION_PYTEST_TARGETS,
    _pytest_cmd,
    _validate_receipts_cmd,
)


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


def test_pytest_cmd_clears_repo_addopts() -> None:
    cmd = _pytest_cmd("-q", "KT_PROD_CLEANROOM/tests")

    assert cmd == [
        "python",
        "-m",
        "pytest",
        "-o",
        "addopts=",
        "-q",
        "KT_PROD_CLEANROOM/tests",
    ]


def test_curated_smoke_targets_are_explicit() -> None:
    assert TEMPLE_PYTEST_TARGETS == (
        "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_schema_contracts.py",
        "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_no_network_dry_run.py",
    )
    assert VERIFICATION_PYTEST_TARGETS == (
        "KT_PROD_CLEANROOM/tools/verification/tests/test_reconcile_and_schemas.py",
        "KT_PROD_CLEANROOM/tools/verification/tests/test_validate_receipts.py",
        "KT_PROD_CLEANROOM/tools/verification/tests/test_validate_council_packet_v1.py",
    )
