from __future__ import annotations

from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()


_FORBIDDEN_NETWORK_IMPORTS = (
    "import requests",
    "from requests",
    "import socket",
    "from socket",
    "import urllib",
    "from urllib",
    "import http.client",
    "from http.client",
    "import aiohttp",
    "from aiohttp",
)


def _read_text(rel: str) -> str:
    return (_REPO_ROOT / rel).read_text(encoding="utf-8", errors="ignore")


@pytest.mark.parametrize(
    "rel",
    [
        "KT_PROD_CLEANROOM/tools/verification/fl4_promote.py",
        "KT_PROD_CLEANROOM/tools/verification/fl4_replay_from_receipts.py",
        "KT_PROD_CLEANROOM/tools/verification/growth_e2e_gate.py",
    ],
)
def test_offline_safe_tools_do_not_import_network_libs(rel: str) -> None:
    text = _read_text(rel)
    assert not any(tok in text for tok in _FORBIDDEN_NETWORK_IMPORTS), f"Forbidden network import detected in {rel}"


def test_replay_and_promotion_do_not_use_wall_clock_directly() -> None:
    for rel in (
        "KT_PROD_CLEANROOM/tools/verification/fl4_promote.py",
        "KT_PROD_CLEANROOM/tools/verification/fl4_replay_from_receipts.py",
    ):
        text = _read_text(rel)
        assert "time.time(" not in text
        assert "datetime.now(" not in text


def test_meta_evaluator_wall_clock_use_is_receipt_only() -> None:
    """
    Meta-evaluator may timestamp its own receipt, but must not consult wall clock for scoring logic.
    This test enforces that datetime.now usage stays confined to receipt construction.
    """
    rel = "KT_PROD_CLEANROOM/tools/verification/fl3_meta_evaluator.py"
    text = _read_text(rel)
    assert text.count("datetime.now(") == 1

