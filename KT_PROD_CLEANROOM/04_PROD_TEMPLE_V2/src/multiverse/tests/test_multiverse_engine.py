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

from multiverse.multiverse_engine import ConstitutionalViolationError, MultiverseEngine  # noqa: E402
from multiverse.multiverse_schemas import (  # noqa: E402
    MAX_CANDIDATES,
    MAX_TOTAL_TOKENS,
    MultiverseCandidateSchema,
    MultiverseEvaluationRequestSchema,
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


def _candidate(*, candidate_id: str, token_count: int, metrics: dict) -> dict:
    return {
        "schema_id": MultiverseCandidateSchema.SCHEMA_ID,
        "schema_version_hash": MultiverseCandidateSchema.SCHEMA_VERSION_HASH,
        "candidate_id": candidate_id,
        "token_count": token_count,
        "metrics": dict(metrics),
    }


def _request(*, candidates: list[dict], metric_names: list[str]) -> dict:
    return {
        "schema_id": MultiverseEvaluationRequestSchema.SCHEMA_ID,
        "schema_version_hash": MultiverseEvaluationRequestSchema.SCHEMA_VERSION_HASH,
        "evaluation_id": "mv.eval.v2",
        "runtime_registry_hash": "1" * 64,
        "metric_names": list(metric_names),
        "candidates": list(candidates),
    }


class TestMultiverseEngineC013(unittest.TestCase):
    def test_unknown_fields_rejected(self) -> None:
        c = _candidate(candidate_id="c1", token_count=1, metrics={"m1": 0.5})
        c["extra"] = "x"
        req = _request(candidates=[c], metric_names=["m1"])
        with self.assertRaises(SchemaValidationError):
            MultiverseEvaluationRequestSchema.from_dict(req)

    def test_oversized_candidate_set_rejected(self) -> None:
        candidates = [
            _candidate(candidate_id=f"c{i}", token_count=1, metrics={"m1": 0.5}) for i in range(MAX_CANDIDATES + 1)
        ]
        req = _request(candidates=candidates, metric_names=["m1"])
        with self.assertRaises(SchemaValidationError):
            MultiverseEvaluationRequestSchema.from_dict(req)

    def test_total_token_cap_rejected(self) -> None:
        big = MAX_TOTAL_TOKENS // 2 + 100
        candidates = [
            _candidate(candidate_id="c1", token_count=big, metrics={"m1": 0.2}),
            _candidate(candidate_id="c2", token_count=big, metrics={"m1": 0.2}),
        ]
        req = _request(candidates=candidates, metric_names=["m1"])
        with self.assertRaises(SchemaValidationError):
            MultiverseEvaluationRequestSchema.from_dict(req)

    def test_order_independence(self) -> None:
        c1 = _candidate(candidate_id="a", token_count=1, metrics={"m1": 0.2, "m2": 0.8})
        c2 = _candidate(candidate_id="b", token_count=1, metrics={"m1": 0.7, "m2": 0.3})
        req1 = MultiverseEvaluationRequestSchema.from_dict(_request(candidates=[c1, c2], metric_names=["m1", "m2"]))
        req2 = MultiverseEvaluationRequestSchema.from_dict(_request(candidates=[c2, c1], metric_names=["m1", "m2"]))
        ctx = _valid_context()
        r1 = MultiverseEngine.evaluate(context=ctx, request=req1).to_dict()
        r2 = MultiverseEngine.evaluate(context=ctx, request=req2).to_dict()
        self.assertEqual(r1, r2)

    def test_determinism_result_hash_100x(self) -> None:
        c1 = _candidate(candidate_id="a", token_count=1, metrics={"m1": 0.2})
        c2 = _candidate(candidate_id="b", token_count=1, metrics={"m1": 0.7})
        req = MultiverseEvaluationRequestSchema.from_dict(_request(candidates=[c1, c2], metric_names=["m1"]))
        ctx = _valid_context()
        hashes = set()
        for _ in range(100):
            r = MultiverseEngine.evaluate(context=ctx, request=req).to_dict()
            hashes.add(r["result_hash"])
        self.assertEqual(len(hashes), 1)

    def test_context_freeze_raises(self) -> None:
        frozen = MultiverseEngine._freeze_context_for_tests(_valid_context())
        with self.assertRaises(ConstitutionalViolationError):
            frozen["schema_id"] = "x"  # type: ignore[index]

    def test_no_network_calls(self) -> None:
        original_socket = socket.socket
        original_create_connection = socket.create_connection

        def raise_network(*_a, **_k):  # type: ignore[no-untyped-def]
            raise NetworkCallAttempted("Network call attempted (fail-closed)")

        socket.socket = raise_network  # type: ignore[assignment]
        socket.create_connection = raise_network  # type: ignore[assignment]
        try:
            c1 = _candidate(candidate_id="a", token_count=1, metrics={"m1": 0.2})
            req = MultiverseEvaluationRequestSchema.from_dict(_request(candidates=[c1], metric_names=["m1"]))
            MultiverseEngine.evaluate(context=_valid_context(), request=req)
        finally:
            socket.socket = original_socket  # type: ignore[assignment]
            socket.create_connection = original_create_connection  # type: ignore[assignment]

    def test_purity_no_state_or_governance_imports(self) -> None:
        original_import = builtins.__import__

        def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):  # type: ignore[no-untyped-def]
            if isinstance(name, str) and (
                name.startswith("governance") or name.startswith("memory") or name.startswith("temporal")
            ):
                raise AssertionError(f"Unexpected import in Multiverse evaluation: {name}")
            return original_import(name, globals, locals, fromlist, level)

        builtins.__import__ = guarded_import  # type: ignore[assignment]
        try:
            c1 = _candidate(candidate_id="a", token_count=1, metrics={"m1": 0.2})
            req = MultiverseEvaluationRequestSchema.from_dict(_request(candidates=[c1], metric_names=["m1"]))
            MultiverseEngine.evaluate(context=_valid_context(), request=req)
        finally:
            builtins.__import__ = original_import  # type: ignore[assignment]
