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

    def test_task_type_changes_with_context_and_condition(self) -> None:
        policy_trigger = ParadoxTriggerSchema.from_dict(_valid_trigger())
        request_trigger = ParadoxTriggerSchema.from_dict({**_valid_trigger(), "subject_hash": "2" * 64, "signal_hash": "3" * 64})
        self_reference_trigger = ParadoxTriggerSchema.from_dict({**_valid_trigger(), "condition": "self_reference", "subject_hash": "4" * 64, "signal_hash": "5" * 64})
        loop_trigger = ParadoxTriggerSchema.from_dict({**_valid_trigger(), "condition": "infinite_loop", "subject_hash": "6" * 64, "signal_hash": "7" * 64})

        policy_result = ParadoxEngine.run(context=_valid_context(input_text="policy evidence contradiction"), trigger=policy_trigger).to_dict()
        request_result = ParadoxEngine.run(context=_valid_context(input_text="request output mismatch"), trigger=request_trigger).to_dict()
        self_reference_result = ParadoxEngine.run(context=_valid_context(input_text="recursive subject"), trigger=self_reference_trigger).to_dict()
        loop_result = ParadoxEngine.run(context=_valid_context(input_text="looping request"), trigger=loop_trigger).to_dict()

        self.assertEqual(policy_result["task"]["task_type"], "POLICY_EVIDENCE_CONFLICT_V1")
        self.assertEqual(request_result["task"]["task_type"], "REQUEST_OUTPUT_CONFLICT_V1")
        self.assertEqual(self_reference_result["task"]["task_type"], "SELF_REFERENCE_GUARD_V1")
        self.assertEqual(loop_result["task"]["task_type"], "LOOP_BUDGET_GUARD_V1")
