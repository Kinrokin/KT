from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path
from typing import Any, Dict


def _add_src_to_syspath() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    src_root = repo_root / "src"
    sys.path.insert(0, str(src_root))


_add_src_to_syspath()

from core.invariants_gate import (  # noqa: E402
    CONSTITUTION_VERSION_HASH,
    ConstitutionalCrisisError,
    ContractViolationError,
    InvariantsGate,
)
from schemas.runtime_context_schema import (  # noqa: E402
    RUNTIME_CONTEXT_SCHEMA_ID,
    RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
)


def _valid_context(*, input_text: str = "") -> Dict[str, Any]:
    return {
        "envelope": {"input": input_text},
        "schema_id": RUNTIME_CONTEXT_SCHEMA_ID,
        "schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
        "constitution_version_hash": CONSTITUTION_VERSION_HASH,
    }


def _purge_training_modules() -> None:
    markers = ("curriculum", "epoch", "dataset", "benchmarks", "trainer", "finetune")
    for name in list(sys.modules.keys()):
        if not name:
            continue
        lowered = name.lower()
        if any(marker in lowered for marker in markers):
            sys.modules.pop(name, None)


class TestInvariantsGate(unittest.TestCase):
    def setUp(self) -> None:
        _purge_training_modules()

    def test_missing_required_fields_fails(self) -> None:
        ctx = _valid_context()
        ctx.pop("schema_id")
        with self.assertRaises(ContractViolationError):
            InvariantsGate.assert_runtime_invariants(ctx)

    def test_invalid_schema_hash_fails(self) -> None:
        ctx = _valid_context()
        ctx["schema_version_hash"] = "0" * 64
        with self.assertRaises(ContractViolationError):
            InvariantsGate.assert_runtime_invariants(ctx)

    def test_runtime_import_bleed_fails(self) -> None:
        injected = "curriculum.fake_module"
        sys.modules[injected] = types.ModuleType(injected)
        try:
            with self.assertRaises(ConstitutionalCrisisError):
                InvariantsGate.assert_runtime_invariants(_valid_context())
        finally:
            sys.modules.pop(injected, None)

    def test_happy_path_passes(self) -> None:
        InvariantsGate.assert_runtime_invariants(_valid_context(input_text=""))


if __name__ == "__main__":
    raise SystemExit(unittest.main())
