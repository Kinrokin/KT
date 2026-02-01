from __future__ import annotations

import socket
from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from tools.verification.io_guard import IOGuard, IOGuardConfig, IOGuardViolation  # noqa: E402


def test_io_guard_blocks_network(tmp_path: Path) -> None:
    with pytest.raises(IOGuardViolation):
        with IOGuard(IOGuardConfig(allowed_write_roots=(tmp_path,), deny_network=True, receipt_path=None)):
            socket.getaddrinfo("example.com", 80)


def test_io_guard_blocks_writes_outside_allowed_roots(tmp_path: Path) -> None:
    allowed = tmp_path / "ok.txt"
    forbidden = Path(_REPO_ROOT) / "FORBIDDEN_WRITE.txt"

    with IOGuard(IOGuardConfig(allowed_write_roots=(tmp_path,), deny_network=False, receipt_path=None)):
        allowed.write_text("ok\n", encoding="utf-8")
        with pytest.raises(IOGuardViolation):
            forbidden.write_text("nope\n", encoding="utf-8")

