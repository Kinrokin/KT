from __future__ import annotations

import builtins
import copy
import socket
import sys
import unittest
from pathlib import Path


def _add_src_to_syspath() -> None:
    src_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(src_root))


_add_src_to_syspath()

from council.council_router import ConstitutionalViolationError, CouncilRouter  # noqa: E402
from council.council_schemas import (  # noqa: E402
    MODE_DRY_RUN,
    MODE_LIVE_REQUESTED,
    PLAN_STATUS_REFUSED,
    RESULT_STATUS_DRY_RUN,
    RESULT_STATUS_REFUSED,
    CouncilPlanSchema,
    CouncilRequestSchema,
)
from schemas.base_schema import SchemaValidationError  # noqa: E402
from schemas.runtime_context_schema import RUNTIME_CONTEXT_SCHEMA_ID, RUNTIME_CONTEXT_SCHEMA_VERSION_HASH  # noqa: E402


class NetworkCallAttempted(RuntimeError):
    pass


def _valid_context() -> dict:
    return {
        "envelope": {"input": ""},
        "schema_id": RUNTIME_CONTEXT_SCHEMA_ID,
        "schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
        "constitution_version_hash": "0" * 64,
    }


def _request(*, mode: str, provider_ids: list[str], fanout_cap: int = 1) -> dict:
    return {
        "schema_id": CouncilRequestSchema.SCHEMA_ID,
        "schema_version_hash": CouncilRequestSchema.SCHEMA_VERSION_HASH,
        "request_id": "council.req.v2",
        "runtime_registry_hash": "1" * 64,
        "mode": mode,
        "provider_ids": list(provider_ids),
        "fanout_cap": fanout_cap,
        "per_call_token_cap": 256,
        "total_token_cap": 1024,
        "input_hash": "2" * 64,
    }


class TestCouncilRouterC014(unittest.TestCase):
    def test_unknown_fields_rejected(self) -> None:
        req = _request(mode=MODE_DRY_RUN, provider_ids=["dry_run"])
        req["extra"] = "x"
        with self.assertRaises(SchemaValidationError):
            CouncilRequestSchema.from_dict(req)

    def test_oversized_field_rejected(self) -> None:
        req = _request(mode=MODE_DRY_RUN, provider_ids=["dry_run"])
        req["request_id"] = "x" * 1000
        with self.assertRaises(SchemaValidationError):
            CouncilRequestSchema.from_dict(req)

    def test_deterministic_plan_hash(self) -> None:
        req = CouncilRequestSchema.from_dict(_request(mode=MODE_DRY_RUN, provider_ids=["dry_run"]))
        ctx = _valid_context()
        p1 = CouncilRouter.plan(context=ctx, request=req).to_dict()
        p2 = CouncilRouter.plan(context=ctx, request=req).to_dict()
        self.assertEqual(p1, p2)

    def test_order_independence_provider_ids(self) -> None:
        req1 = CouncilRequestSchema.from_dict(
            _request(mode=MODE_DRY_RUN, provider_ids=["dry_run_alt", "dry_run"], fanout_cap=2)
        )
        req2 = CouncilRequestSchema.from_dict(
            _request(mode=MODE_DRY_RUN, provider_ids=["dry_run", "dry_run_alt"], fanout_cap=2)
        )
        ctx = _valid_context()
        p1 = CouncilRouter.plan(context=ctx, request=req1).to_dict()
        p2 = CouncilRouter.plan(context=ctx, request=req2).to_dict()
        self.assertEqual(p1["plan_hash"], p2["plan_hash"])

    def test_fanout_cap_enforced(self) -> None:
        req = _request(mode=MODE_DRY_RUN, provider_ids=["dry_run", "dry_run"], fanout_cap=1)
        with self.assertRaises(SchemaValidationError):
            CouncilRequestSchema.from_dict(req)

    def test_budget_caps_enforced(self) -> None:
        req = _request(mode=MODE_DRY_RUN, provider_ids=["dry_run"])
        req["per_call_token_cap"] = 2000
        req["total_token_cap"] = 1000
        with self.assertRaises(SchemaValidationError):
            CouncilRequestSchema.from_dict(req)

    def test_live_mode_refused_no_silent_mocks(self) -> None:
        req = CouncilRequestSchema.from_dict(_request(mode=MODE_LIVE_REQUESTED, provider_ids=["dry_run"]))
        ctx = _valid_context()
        plan = CouncilRouter.plan(context=ctx, request=req).to_dict()
        self.assertEqual(plan["status"], PLAN_STATUS_REFUSED)
        res = CouncilRouter.execute(context=ctx, plan=CouncilPlanSchema.from_dict(plan)).to_dict()
        self.assertEqual(res["status"], RESULT_STATUS_REFUSED)

    def test_dry_run_execute_no_fabricated_outputs(self) -> None:
        req = CouncilRequestSchema.from_dict(_request(mode=MODE_DRY_RUN, provider_ids=["dry_run"]))
        ctx = _valid_context()
        plan = CouncilRouter.plan(context=ctx, request=req)
        res = CouncilRouter.execute(context=ctx, plan=plan).to_dict()
        self.assertEqual(res["status"], RESULT_STATUS_DRY_RUN)
        self.assertEqual(res["calls"], [])
        self.assertEqual(res["output_hashes"], [])

    def test_context_freeze_raises(self) -> None:
        frozen = CouncilRouter._freeze_context_for_tests(_valid_context())
        with self.assertRaises(ConstitutionalViolationError):
            frozen["schema_id"] = "x"  # type: ignore[index]

    def test_context_not_mutated(self) -> None:
        ctx = _valid_context()
        before = copy.deepcopy(ctx)
        req = CouncilRequestSchema.from_dict(_request(mode=MODE_DRY_RUN, provider_ids=["dry_run"]))
        plan = CouncilRouter.plan(context=ctx, request=req)
        _ = CouncilRouter.execute(context=ctx, plan=plan)
        self.assertEqual(ctx, before)

    def test_no_network_calls(self) -> None:
        original_socket = socket.socket
        original_create_connection = socket.create_connection

        def raise_network(*_a, **_k):  # type: ignore[no-untyped-def]
            raise NetworkCallAttempted("Network call attempted (fail-closed)")

        socket.socket = raise_network  # type: ignore[assignment]
        socket.create_connection = raise_network  # type: ignore[assignment]
        try:
            req = CouncilRequestSchema.from_dict(_request(mode=MODE_DRY_RUN, provider_ids=["dry_run"]))
            ctx = _valid_context()
            plan = CouncilRouter.plan(context=ctx, request=req)
            CouncilRouter.execute(context=ctx, plan=plan)
        finally:
            socket.socket = original_socket  # type: ignore[assignment]
            socket.create_connection = original_create_connection  # type: ignore[assignment]

    def test_purity_no_state_or_governance_imports(self) -> None:
        original_import = builtins.__import__

        def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):  # type: ignore[no-untyped-def]
            if isinstance(name, str) and (
                name.startswith("governance") or name.startswith("memory") or name.startswith("temporal")
            ):
                raise AssertionError(f"Unexpected import in Council routing: {name}")
            return original_import(name, globals, locals, fromlist, level)

        builtins.__import__ = guarded_import  # type: ignore[assignment]
        try:
            req = CouncilRequestSchema.from_dict(_request(mode=MODE_DRY_RUN, provider_ids=["dry_run"]))
            ctx = _valid_context()
            plan = CouncilRouter.plan(context=ctx, request=req)
            CouncilRouter.execute(context=ctx, plan=plan)
        finally:
            builtins.__import__ = original_import  # type: ignore[assignment]
