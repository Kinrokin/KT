from __future__ import annotations

import socket
import sys
import unittest
from pathlib import Path


def _add_src_to_syspath() -> None:
    src_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(src_root))


_add_src_to_syspath()

from paradox.paradox_engine import ParadoxEngine  # noqa: E402
from paradox.paradox_schemas import ParadoxTriggerSchema  # noqa: E402
from schemas.base_schema import SchemaValidationError  # noqa: E402
from schemas.runtime_context_schema import RUNTIME_CONTEXT_SCHEMA_ID, RUNTIME_CONTEXT_SCHEMA_VERSION_HASH  # noqa: E402
from schemas.schema_hash import canonical_json  # noqa: E402


class NetworkCallAttempted(RuntimeError):
    pass


def _valid_context(*, input_text: str = "") -> dict:
    return {
        "envelope": {"input": input_text},
        "schema_id": RUNTIME_CONTEXT_SCHEMA_ID,
        "schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
        "constitution_version_hash": "0" * 64,
    }


def _valid_trigger() -> dict:
    return {
        "schema_id": ParadoxTriggerSchema.SCHEMA_ID,
        "schema_version_hash": ParadoxTriggerSchema.SCHEMA_VERSION_HASH,
        "trigger_type": "PARADOX_SIGNAL",
        "condition": "contradiction",
        "severity": 7,
        "confidence": 80,
        "subject_hash": "0" * 64,
        "signal_hash": "1" * 64,
    }


class TestParadoxEngineC011(unittest.TestCase):
    def test_unknown_trigger_fields_rejected(self) -> None:
        payload = _valid_trigger()
        payload["extra"] = "x"
        with self.assertRaises(SchemaValidationError):
            ParadoxTriggerSchema.from_dict(payload)

    def test_oversized_trigger_rejected(self) -> None:
        payload = _valid_trigger()
        payload["condition"] = "x" * 1000
        with self.assertRaises(SchemaValidationError):
            ParadoxTriggerSchema.from_dict(payload)

    def test_raw_content_field_rejected(self) -> None:
        payload = _valid_trigger()
        payload["prompt"] = "raw"
        with self.assertRaises(SchemaValidationError):
            ParadoxTriggerSchema.from_dict(payload)

    def test_determinism_identical_trigger_same_task_hash(self) -> None:
        ctx = _valid_context()
        trigger = ParadoxTriggerSchema.from_dict(_valid_trigger())
        r1 = ParadoxEngine.run(context=ctx, trigger=trigger).to_dict()
        r2 = ParadoxEngine.run(context=ctx, trigger=trigger).to_dict()
        self.assertEqual(r1["task_hash"], r2["task_hash"])
        self.assertEqual(r1["result_hash"], r2["result_hash"])

    def test_no_network_calls(self) -> None:
        original_socket = socket.socket
        original_create_connection = socket.create_connection

        def raise_network(*_a, **_k):  # type: ignore[no-untyped-def]
            raise NetworkCallAttempted("Network call attempted (fail-closed)")

        socket.socket = raise_network  # type: ignore[assignment]
        socket.create_connection = raise_network  # type: ignore[assignment]
        try:
            ctx = _valid_context()
            trigger = ParadoxTriggerSchema.from_dict(_valid_trigger())
            ParadoxEngine.run(context=ctx, trigger=trigger)
        finally:
            socket.socket = original_socket  # type: ignore[assignment]
            socket.create_connection = original_create_connection  # type: ignore[assignment]

    def test_context_not_mutated(self) -> None:
        ctx = _valid_context()
        before = canonical_json(ctx)
        trigger = ParadoxTriggerSchema.from_dict(_valid_trigger())
        ParadoxEngine.run(context=ctx, trigger=trigger)
        after = canonical_json(ctx)
        self.assertEqual(before, after)

