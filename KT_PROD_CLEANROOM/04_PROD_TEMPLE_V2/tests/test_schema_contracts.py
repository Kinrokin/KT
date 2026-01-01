from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import Any, Dict


def _add_src_to_syspath() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    src_root = repo_root / "src"
    sys.path.insert(0, str(src_root))


_add_src_to_syspath()

from schemas.base_schema import SchemaRegistryError, SchemaValidationError  # noqa: E402
from schemas.runtime_context_schema import (  # noqa: E402
    RUNTIME_CONTEXT_SCHEMA_ID,
    RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
    RUNTIME_CONTEXT_MAX_INPUT_BYTES,
    validate_runtime_context,
)
from schemas.schema_registry import validate_schema_binding  # noqa: E402


def _valid_runtime_context(*, input_text: str = "") -> Dict[str, Any]:
    return {
        "envelope": {"input": input_text},
        "schema_id": RUNTIME_CONTEXT_SCHEMA_ID,
        "schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
        "constitution_version_hash": "0" * 64,
    }


class TestSchemaContracts(unittest.TestCase):
    def test_unknown_schema_id_rejected(self) -> None:
        with self.assertRaises(SchemaRegistryError):
            validate_schema_binding("kt.unknown_schema.v1", "0" * 64)

    def test_wrong_schema_version_hash_rejected(self) -> None:
        with self.assertRaises(SchemaRegistryError):
            validate_schema_binding(RUNTIME_CONTEXT_SCHEMA_ID, "0" * 64)

    def test_unknown_fields_rejected(self) -> None:
        ctx = _valid_runtime_context()
        ctx["extra"] = "x"
        with self.assertRaises(SchemaValidationError):
            validate_runtime_context(ctx)

    def test_missing_required_fields_rejected(self) -> None:
        ctx = _valid_runtime_context()
        ctx.pop("envelope")
        with self.assertRaises(SchemaValidationError):
            validate_runtime_context(ctx)

    def test_oversized_payload_rejected(self) -> None:
        ctx = _valid_runtime_context(input_text=("x" * (RUNTIME_CONTEXT_MAX_INPUT_BYTES + 1)))
        with self.assertRaises(SchemaValidationError):
            validate_runtime_context(ctx)


if __name__ == "__main__":
    raise SystemExit(unittest.main())

