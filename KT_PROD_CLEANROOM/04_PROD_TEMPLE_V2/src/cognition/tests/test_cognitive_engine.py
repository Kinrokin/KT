from __future__ import annotations

import builtins
import copy
import socket
import sys
import time
import unittest
from pathlib import Path


def _add_src_to_syspath() -> None:
    src_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(src_root))


_add_src_to_syspath()

from cognition.cognitive_engine import ConstitutionalViolationError, CognitiveEngine  # noqa: E402
from cognition.cognitive_schemas import (  # noqa: E402
    MODE_DRY_RUN,
    MODE_LIVE_REQUESTED,
    PLAN_STATUS_REFUSED,
    REFUSE_EXTERNAL_UNAVAILABLE,
    REFUSE_ILLEGAL_REFERENCE,
    CognitivePlanSchema,
    CognitiveRequestSchema,
)
from schemas.schema_hash import sha256_json  # noqa: E402
from schemas.base_schema import SchemaValidationError  # noqa: E402
from schemas.runtime_context_schema import RUNTIME_CONTEXT_SCHEMA_ID, RUNTIME_CONTEXT_SCHEMA_VERSION_HASH  # noqa: E402


class NetworkCallAttempted(RuntimeError):
    pass


RAW_MARKERS = ("prompt", "messages", "content", "reasoning", "thought")


def _valid_context() -> dict:
    return {
        "envelope": {"input": ""},
        "schema_id": RUNTIME_CONTEXT_SCHEMA_ID,
        "schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
        "constitution_version_hash": "0" * 64,
    }


def _request(*, mode: str, artifact_ids: list[str] | None = None) -> dict:
    refs = []
    for idx, aid in enumerate(artifact_ids or []):
        refs.append({"artifact_id": aid, "artifact_hash": f"{idx + 1:x}".zfill(64)})
    return {
        "schema_id": CognitiveRequestSchema.SCHEMA_ID,
        "schema_version_hash": CognitiveRequestSchema.SCHEMA_VERSION_HASH,
        "request_id": "cog.req.v2",
        "runtime_registry_hash": "1" * 64,
        "mode": mode,
        "input_hash": "2" * 64,
        "max_steps": 4,
        "max_branching": 1,
        "max_depth": 4,
        "artifact_refs": refs,
    }


def _assert_no_raw_markers(obj: object) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).lower()
            if any(m in kl for m in RAW_MARKERS):
                raise AssertionError(f"Raw marker key leaked: {k!r}")
            _assert_no_raw_markers(v)
    elif isinstance(obj, list):
        for item in obj:
            _assert_no_raw_markers(item)
    elif isinstance(obj, str):
        if len(obj) > 512:
            raise AssertionError("Overlong string leaked in cognitive outputs")


class TestCognitiveEngineC015(unittest.TestCase):
    def test_unknown_fields_rejected(self) -> None:
        req = _request(mode=MODE_DRY_RUN)
        req["extra"] = "x"
        with self.assertRaises(SchemaValidationError):
            CognitiveRequestSchema.from_dict(req)

    def test_hash_only_planning_rejects_raw_content_refs(self) -> None:
        req = _request(mode=MODE_DRY_RUN)
        req["artifact_refs"] = [{"artifact_id": "x", "artifact_hash": "1" * 64, "content": "RAW"}]
        with self.assertRaises(SchemaValidationError):
            CognitiveRequestSchema.from_dict(req)

    def test_oversized_bounds_rejected(self) -> None:
        req = _request(mode=MODE_DRY_RUN)
        req["max_steps"] = 999
        with self.assertRaises(SchemaValidationError):
            CognitiveRequestSchema.from_dict(req)

    def test_deterministic_plan_hash(self) -> None:
        req = CognitiveRequestSchema.from_dict(_request(mode=MODE_DRY_RUN, artifact_ids=["paradox.trigger"]))
        ctx = _valid_context()
        p1 = CognitiveEngine.plan(context=ctx, request=req).to_dict()
        p2 = CognitiveEngine.plan(context=ctx, request=req).to_dict()
        self.assertEqual(p1, p2)

    def test_live_mode_refused(self) -> None:
        req = CognitiveRequestSchema.from_dict(_request(mode=MODE_LIVE_REQUESTED))
        ctx = _valid_context()
        plan = CognitiveEngine.plan(context=ctx, request=req).to_dict()
        self.assertEqual(plan["status"], PLAN_STATUS_REFUSED)
        self.assertEqual(plan["refusal_code"], REFUSE_EXTERNAL_UNAVAILABLE)

    def test_illegal_reference_refused(self) -> None:
        req = CognitiveRequestSchema.from_dict(_request(mode=MODE_DRY_RUN, artifact_ids=["cognition.foo"]))
        ctx = _valid_context()
        plan = CognitiveEngine.plan(context=ctx, request=req).to_dict()
        self.assertEqual(plan["status"], PLAN_STATUS_REFUSED)
        self.assertEqual(plan["refusal_code"], REFUSE_ILLEGAL_REFERENCE)

    def test_execute_deterministic_result_hash_100x(self) -> None:
        req = CognitiveRequestSchema.from_dict(_request(mode=MODE_DRY_RUN, artifact_ids=["paradox.trigger"]))
        ctx = _valid_context()
        plan = CognitiveEngine.plan(context=ctx, request=req)
        hashes = set()
        for _ in range(100):
            r = CognitiveEngine.execute(context=ctx, plan=plan).to_dict()
            hashes.add(r["result_hash"])
        self.assertEqual(len(hashes), 1)

    def test_no_time_dependence(self) -> None:
        original_time = time.time
        original_perf = time.perf_counter
        original_sleep = time.sleep

        def raise_time(*_a, **_k):  # type: ignore[no-untyped-def]
            raise RuntimeError("Wall-clock access attempted (fail-closed)")

        time.time = raise_time  # type: ignore[assignment]
        time.perf_counter = raise_time  # type: ignore[assignment]
        time.sleep = raise_time  # type: ignore[assignment]
        try:
            req = CognitiveRequestSchema.from_dict(_request(mode=MODE_DRY_RUN))
            ctx = _valid_context()
            plan = CognitiveEngine.plan(context=ctx, request=req)
            _ = CognitiveEngine.execute(context=ctx, plan=plan)
        finally:
            time.time = original_time  # type: ignore[assignment]
            time.perf_counter = original_perf  # type: ignore[assignment]
            time.sleep = original_sleep  # type: ignore[assignment]

    def test_no_network_calls(self) -> None:
        original_socket = socket.socket
        original_create_connection = socket.create_connection

        def raise_network(*_a, **_k):  # type: ignore[no-untyped-def]
            raise NetworkCallAttempted("Network call attempted (fail-closed)")

        socket.socket = raise_network  # type: ignore[assignment]
        socket.create_connection = raise_network  # type: ignore[assignment]
        try:
            req = CognitiveRequestSchema.from_dict(_request(mode=MODE_DRY_RUN))
            ctx = _valid_context()
            plan = CognitiveEngine.plan(context=ctx, request=req)
            _ = CognitiveEngine.execute(context=ctx, plan=plan)
        finally:
            socket.socket = original_socket  # type: ignore[assignment]
            socket.create_connection = original_create_connection  # type: ignore[assignment]

    def test_context_freeze_raises(self) -> None:
        frozen = CognitiveEngine._freeze_context_for_tests(_valid_context())
        with self.assertRaises(ConstitutionalViolationError):
            frozen["schema_id"] = "x"  # type: ignore[index]

    def test_context_not_mutated(self) -> None:
        ctx = _valid_context()
        before = copy.deepcopy(ctx)
        req = CognitiveRequestSchema.from_dict(_request(mode=MODE_DRY_RUN))
        plan = CognitiveEngine.plan(context=ctx, request=req)
        _ = CognitiveEngine.execute(context=ctx, plan=plan)
        self.assertEqual(ctx, before)

    def test_no_chain_of_thought_leakage(self) -> None:
        req = CognitiveRequestSchema.from_dict(_request(mode=MODE_DRY_RUN))
        ctx = _valid_context()
        plan = CognitiveEngine.plan(context=ctx, request=req)
        result = CognitiveEngine.execute(context=ctx, plan=plan).to_dict()
        _assert_no_raw_markers(plan.to_dict())
        _assert_no_raw_markers(result)

    def test_step_isolation_no_cross_step_memory(self) -> None:
        # If step 0 changes, step 1 must remain identical.
        step0 = {"step_index": 0, "step_type": "DECOMPOSE", "step_hash": sha256_json({"s": 0, "x": 1})}
        step1 = {"step_index": 1, "step_type": "EVALUATE", "step_hash": sha256_json({"s": 1, "x": 1})}
        payload = {
            "schema_id": CognitivePlanSchema.SCHEMA_ID,
            "schema_version_hash": CognitivePlanSchema.SCHEMA_VERSION_HASH,
            "plan_id": "cog.plan.v2",
            "runtime_registry_hash": "1" * 64,
            "request_hash": "2" * 64,
            "status": "OK",
            "mode": MODE_DRY_RUN,
            "steps": [step0, step1],
            "plan_hash": "",
        }
        payload["plan_hash"] = CognitivePlanSchema.compute_plan_hash(payload)
        plan_a = CognitivePlanSchema.from_dict(payload)
        res_a = CognitiveEngine.execute(context=_valid_context(), plan=plan_a).to_dict()

        payload2 = copy.deepcopy(payload)
        payload2["steps"][0]["step_hash"] = sha256_json({"s": 0, "x": 999})
        payload2["plan_hash"] = CognitivePlanSchema.compute_plan_hash(payload2)
        plan_b = CognitivePlanSchema.from_dict(payload2)
        res_b = CognitiveEngine.execute(context=_valid_context(), plan=plan_b).to_dict()

        step_a = next(s for s in res_a["steps"] if s["step_index"] == 1)
        step_b = next(s for s in res_b["steps"] if s["step_index"] == 1)
        self.assertEqual(step_a, step_b)

    def test_purity_no_state_or_governance_imports(self) -> None:
        original_import = builtins.__import__

        def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):  # type: ignore[no-untyped-def]
            if isinstance(name, str) and (
                name.startswith("governance") or name.startswith("memory") or name.startswith("temporal")
            ):
                raise AssertionError(f"Unexpected import in Cognitive planning/execution: {name}")
            return original_import(name, globals, locals, fromlist, level)

        builtins.__import__ = guarded_import  # type: ignore[assignment]
        try:
            req = CognitiveRequestSchema.from_dict(_request(mode=MODE_DRY_RUN))
            ctx = _valid_context()
            plan = CognitiveEngine.plan(context=ctx, request=req)
            _ = CognitiveEngine.execute(context=ctx, plan=plan)
        finally:
            builtins.__import__ = original_import  # type: ignore[assignment]
