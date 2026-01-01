from __future__ import annotations

import builtins
import socket
import sys
import unittest
from pathlib import Path


def _add_src_to_syspath() -> None:
    src_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(src_root))


_add_src_to_syspath()

from schemas.base_schema import SchemaValidationError  # noqa: E402
from thermodynamics.budget_engine import BudgetEngine  # noqa: E402
from thermodynamics.budget_schemas import (  # noqa: E402
    REFUSE_DURATION_EXCEEDED,
    REFUSE_NESTED_ALLOCATION,
    REFUSE_STEPS_EXCEEDED,
    REFUSE_TOKENS_EXCEEDED,
    STATUS_OK,
    STATUS_REFUSED,
    BudgetAllocationSchema,
    BudgetConsumptionSchema,
    BudgetRequestSchema,
    MAX_TOKEN_CEILING,
)


class NetworkCallAttempted(RuntimeError):
    pass


def _valid_context() -> dict:
    # Budget engine is semantics-blind; only schema/constitution identifiers are read.
    return {
        "envelope": {"input": ""},
        "schema_id": "kt.runtime_context.v1",
        "schema_version_hash": "0" * 64,
        "constitution_version_hash": "0" * 64,
    }


def _request(**overrides):  # type: ignore[no-untyped-def]
    payload = {
        "schema_id": BudgetRequestSchema.SCHEMA_ID,
        "schema_version_hash": BudgetRequestSchema.SCHEMA_VERSION_HASH,
        "request_id": "budget.req.test",
        "runtime_registry_hash": "1" * 64,
        "token_ceiling": 64,
        "step_ceiling": 4,
        "branch_ceiling": 2,
        "memory_ceiling_bytes": 1024,
        "duration_ceiling_millis": 1000,
        "parent_allocation_hash": "0" * 64,
    }
    payload.update(overrides)
    return payload


def _usage(  # noqa: PLR0913
    *,
    allocation_hash: str,
    tokens_used: int,
    steps_used: int,
    branches_used: int = 0,
    bytes_used: int = 0,
    millis_used: int = 0,
) -> dict:
    return {
        "schema_id": BudgetConsumptionSchema.SCHEMA_ID,
        "schema_version_hash": BudgetConsumptionSchema.SCHEMA_VERSION_HASH,
        "allocation_hash": allocation_hash,
        "tokens_used": tokens_used,
        "steps_used": steps_used,
        "branches_used": branches_used,
        "memory_bytes_used": bytes_used,
        "duration_millis_used": millis_used,
    }


class TestBudgetEngineC017(unittest.TestCase):
    def test_unknown_fields_rejected(self) -> None:
        req = _request()
        req["extra"] = "x"
        with self.assertRaises(SchemaValidationError):
            BudgetRequestSchema.from_dict(req)

    def test_allocation_determinism_hash_stable(self) -> None:
        ctx = _valid_context()
        req = BudgetRequestSchema.from_dict(_request())
        hashes = set()
        for _ in range(25):
            alloc = BudgetEngine.allocate(context=ctx, request=req).to_dict()
            self.assertEqual(alloc["status"], STATUS_OK)
            hashes.add(alloc["allocation_hash"])
        self.assertEqual(len(hashes), 1)

    def test_nested_allocation_refused(self) -> None:
        ctx = _valid_context()
        req = BudgetRequestSchema.from_dict(_request(parent_allocation_hash="2" * 64))
        alloc = BudgetEngine.allocate(context=ctx, request=req).to_dict()
        self.assertEqual(alloc["status"], STATUS_REFUSED)
        self.assertEqual(alloc["refusal_code"], REFUSE_NESTED_ALLOCATION)

    def test_incremental_steps_preemptive_refusal(self) -> None:
        ctx = _valid_context()
        req = BudgetRequestSchema.from_dict(_request(step_ceiling=2))
        alloc_obj = BudgetEngine.allocate(context=ctx, request=req)
        alloc = alloc_obj.to_dict()

        ok = BudgetEngine.consume(
            context=ctx,
            allocation=BudgetAllocationSchema.from_dict(alloc),
            usage=BudgetConsumptionSchema.from_dict(
                _usage(allocation_hash=alloc["allocation_hash"], tokens_used=0, steps_used=2)
            ),
        ).to_dict()
        self.assertEqual(ok["status"], STATUS_OK)
        self.assertEqual(ok["steps_remaining"], 0)

        refused = BudgetEngine.consume(
            context=ctx,
            allocation=BudgetAllocationSchema.from_dict(alloc),
            usage=BudgetConsumptionSchema.from_dict(
                _usage(allocation_hash=alloc["allocation_hash"], tokens_used=0, steps_used=3)
            ),
        ).to_dict()
        self.assertEqual(refused["status"], STATUS_REFUSED)
        self.assertEqual(refused["refusal_code"], REFUSE_STEPS_EXCEEDED)

    def test_token_overconsumption_refused(self) -> None:
        ctx = _valid_context()
        req = BudgetRequestSchema.from_dict(_request(token_ceiling=1))
        alloc = BudgetEngine.allocate(context=ctx, request=req).to_dict()
        refused = BudgetEngine.consume(
            context=ctx,
            allocation=BudgetAllocationSchema.from_dict(alloc),
            usage=BudgetConsumptionSchema.from_dict(
                _usage(allocation_hash=alloc["allocation_hash"], tokens_used=2, steps_used=0)
            ),
        ).to_dict()
        self.assertEqual(refused["status"], STATUS_REFUSED)
        self.assertEqual(refused["refusal_code"], REFUSE_TOKENS_EXCEEDED)

    def test_no_negative_usage(self) -> None:
        alloc = BudgetEngine.allocate(context=_valid_context(), request=BudgetRequestSchema.from_dict(_request())).to_dict()
        bad = _usage(allocation_hash=alloc["allocation_hash"], tokens_used=-1, steps_used=0)
        with self.assertRaises(SchemaValidationError):
            BudgetConsumptionSchema.from_dict(bad)

    def test_duration_fuse_refusal(self) -> None:
        ctx = _valid_context()
        req = BudgetRequestSchema.from_dict(_request(duration_ceiling_millis=5))
        alloc = BudgetEngine.allocate(context=ctx, request=req).to_dict()
        refused = BudgetEngine.consume(
            context=ctx,
            allocation=BudgetAllocationSchema.from_dict(alloc),
            usage=BudgetConsumptionSchema.from_dict(
                _usage(allocation_hash=alloc["allocation_hash"], tokens_used=0, steps_used=0, millis_used=6)
            ),
        ).to_dict()
        self.assertEqual(refused["status"], STATUS_REFUSED)
        self.assertEqual(refused["refusal_code"], REFUSE_DURATION_EXCEEDED)

    def test_no_network_calls(self) -> None:
        original_socket = socket.socket
        original_create_connection = socket.create_connection

        def raise_network(*_a, **_k):  # type: ignore[no-untyped-def]
            raise NetworkCallAttempted("Network call attempted (fail-closed)")

        socket.socket = raise_network  # type: ignore[assignment]
        socket.create_connection = raise_network  # type: ignore[assignment]
        try:
            ctx = _valid_context()
            req = BudgetRequestSchema.from_dict(_request())
            alloc = BudgetEngine.allocate(context=ctx, request=req)
            _ = BudgetEngine.consume(
                context=ctx,
                allocation=alloc,
                usage=BudgetConsumptionSchema.from_dict(_usage(allocation_hash=alloc.data["allocation_hash"], tokens_used=0, steps_used=0)),
            )
        finally:
            socket.socket = original_socket  # type: ignore[assignment]
            socket.create_connection = original_create_connection  # type: ignore[assignment]

    def test_purity_no_state_or_governance_imports(self) -> None:
        original_import = builtins.__import__

        def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):  # type: ignore[no-untyped-def]
            if isinstance(name, str) and (name.startswith("governance") or name.startswith("memory")):
                raise AssertionError(f"Unexpected import in Budget engine: {name}")
            return original_import(name, globals, locals, fromlist, level)

        builtins.__import__ = guarded_import  # type: ignore[assignment]
        try:
            ctx = _valid_context()
            req = BudgetRequestSchema.from_dict(_request(token_ceiling=MAX_TOKEN_CEILING))
            _ = BudgetEngine.allocate(context=ctx, request=req)
        finally:
            builtins.__import__ = original_import  # type: ignore[assignment]

