from __future__ import annotations

import re
import unittest
from pathlib import Path
import sys


def _add_repo_root_to_syspath() -> Path:
    # .../tools/growth/orchestrator/tests/test_invocation_contract.py -> repo root
    repo_root = Path(__file__).resolve().parents[4]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    return repo_root


REPO_ROOT = _add_repo_root_to_syspath()

from tools.growth.orchestrator.epoch_orchestrator import _assert_cli_schema  # noqa: E402
from tools.growth.orchestrator.epoch_schemas import EpochSchemaError  # noqa: E402


class TestCliSchemaLock(unittest.TestCase):
    def test_unknown_flag_rejected(self) -> None:
        with self.assertRaises(EpochSchemaError):
            _assert_cli_schema(["--epoch", "x.json", "--unknown-flag"])

    def test_known_flags_allowed(self) -> None:
        _assert_cli_schema(["--epoch", "x.json", "--mode", "salvage", "--summary-only"])


class TestInvocationContract(unittest.TestCase):
    def test_no_epoch_orchestrator_subprocess_calls(self) -> None:
        root = REPO_ROOT / "KT_PROD_CLEANROOM" / "tools" / "growth"
        offenders = []
        for path in root.rglob("*.py"):
            if path.name == "test_invocation_contract.py":
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            if re.search(r"(?<!test_)epoch_orchestrator\\.py", text):
                offenders.append(str(path.relative_to(REPO_ROOT)))
            if "\"--salvage\"" in text or "'--salvage'" in text:
                offenders.append(str(path.relative_to(REPO_ROOT)))
        offenders = sorted(set(offenders))
        if offenders:
            raise AssertionError(f"CLI contract drift (use run_epoch_from_plan instead): {offenders}")
