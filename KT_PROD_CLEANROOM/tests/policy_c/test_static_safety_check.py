from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = ROOT / "04_PROD_TEMPLE_V2" / "src"
sys.path.insert(0, str(SRC_ROOT))
sys.path.insert(0, str(ROOT))

from core.runtime_registry import load_runtime_registry  # noqa: E402
from policy_c.static_safety_check import run_static_safety_check  # noqa: E402


class TestStaticSafetyCheck(unittest.TestCase):
    def test_forbidden_import_detected(self) -> None:
        registry = load_runtime_registry()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad_module.py"
            p.write_text("import socket\n", encoding="utf-8")
            result = run_static_safety_check(registry=registry, module_paths=[p])
            self.assertFalse(result.ok)
            self.assertTrue(any("socket" in e for e in result.errors))


if __name__ == "__main__":
    raise SystemExit(unittest.main())
