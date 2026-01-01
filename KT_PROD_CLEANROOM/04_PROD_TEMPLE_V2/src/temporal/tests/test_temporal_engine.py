from __future__ import annotations

import socket
import sys
import unittest
from pathlib import Path


def _add_src_to_syspath() -> None:
    src_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(src_root))


_add_src_to_syspath()

from schemas.schema_hash import canonical_json  # noqa: E402
from schemas.runtime_context_schema import RUNTIME_CONTEXT_SCHEMA_ID, RUNTIME_CONTEXT_SCHEMA_VERSION_HASH  # noqa: E402
from temporal.temporal_engine import TemporalEngine  # noqa: E402
from temporal.temporal_schemas import (  # noqa: E402
    TemporalForkRequestSchema,
    TemporalReplayRequestSchema,
)
from schemas.base_schema import SchemaValidationError  # noqa: E402


class NetworkCallAttempted(RuntimeError):
    pass


def _valid_context() -> dict:
    return {
        "envelope": {"input": ""},
        "schema_id": RUNTIME_CONTEXT_SCHEMA_ID,
        "schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
        "constitution_version_hash": "0" * 64,
    }


def _valid_fork_request() -> dict:
    return {
        "schema_id": TemporalForkRequestSchema.SCHEMA_ID,
        "schema_version_hash": TemporalForkRequestSchema.SCHEMA_VERSION_HASH,
        "trace_id": "t.v2",
        "epoch_id": "e.0",
        "runtime_registry_hash": "1" * 64,
        "anchor_hash": "2" * 64,
        "parent_fork_hash": None,
    }


class TestTemporalEngineC012(unittest.TestCase):
    def test_unknown_fields_rejected(self) -> None:
        payload = _valid_fork_request()
        payload["extra"] = "x"
        with self.assertRaises(SchemaValidationError):
            TemporalForkRequestSchema.from_dict(payload)

    def test_raw_text_disallowed_by_schema(self) -> None:
        payload = _valid_fork_request()
        payload["note"] = "hello world"
        with self.assertRaises(SchemaValidationError):
            TemporalForkRequestSchema.from_dict(payload)

    def test_oversized_identifier_rejected(self) -> None:
        payload = _valid_fork_request()
        payload["trace_id"] = "x" * 1000
        with self.assertRaises(SchemaValidationError):
            TemporalForkRequestSchema.from_dict(payload)

    def test_deterministic_fork_hash(self) -> None:
        ctx = _valid_context()
        req = TemporalForkRequestSchema.from_dict(_valid_fork_request())
        f1 = TemporalEngine.create_fork(context=ctx, request=req).to_dict()
        f2 = TemporalEngine.create_fork(context=ctx, request=req).to_dict()
        self.assertEqual(f1["fork_hash"], f2["fork_hash"])

    def test_deterministic_replay_hash(self) -> None:
        ctx = _valid_context()
        req = TemporalForkRequestSchema.from_dict(_valid_fork_request())
        fork = TemporalEngine.create_fork(context=ctx, request=req).to_dict()
        replay_req_dict = {
            "schema_id": TemporalReplayRequestSchema.SCHEMA_ID,
            "schema_version_hash": TemporalReplayRequestSchema.SCHEMA_VERSION_HASH,
            "fork": fork,
            "replay_mode": "DRY_RUN",
            "runtime_registry_hash": "1" * 64,
            "max_steps": 0,
        }
        rr = TemporalReplayRequestSchema.from_dict(replay_req_dict)
        r1 = TemporalEngine.replay(context=ctx, request=rr).to_dict()
        r2 = TemporalEngine.replay(context=ctx, request=rr).to_dict()
        self.assertEqual(r1["replay_hash"], r2["replay_hash"])
        self.assertEqual(r1["outcome_hash"], r2["outcome_hash"])

    def test_no_network_calls(self) -> None:
        original_socket = socket.socket
        original_create_connection = socket.create_connection

        def raise_network(*_a, **_k):  # type: ignore[no-untyped-def]
            raise NetworkCallAttempted("Network call attempted (fail-closed)")

        socket.socket = raise_network  # type: ignore[assignment]
        socket.create_connection = raise_network  # type: ignore[assignment]
        try:
            ctx = _valid_context()
            req = TemporalForkRequestSchema.from_dict(_valid_fork_request())
            fork = TemporalEngine.create_fork(context=ctx, request=req).to_dict()
            replay_req_dict = {
                "schema_id": TemporalReplayRequestSchema.SCHEMA_ID,
                "schema_version_hash": TemporalReplayRequestSchema.SCHEMA_VERSION_HASH,
                "fork": fork,
                "replay_mode": "DRY_RUN",
                "runtime_registry_hash": "1" * 64,
                "max_steps": 0,
            }
            rr = TemporalReplayRequestSchema.from_dict(replay_req_dict)
            TemporalEngine.replay(context=ctx, request=rr)
        finally:
            socket.socket = original_socket  # type: ignore[assignment]
            socket.create_connection = original_create_connection  # type: ignore[assignment]

    def test_context_not_mutated(self) -> None:
        ctx = _valid_context()
        before = canonical_json(ctx)
        req = TemporalForkRequestSchema.from_dict(_valid_fork_request())
        fork = TemporalEngine.create_fork(context=ctx, request=req).to_dict()
        replay_req_dict = {
            "schema_id": TemporalReplayRequestSchema.SCHEMA_ID,
            "schema_version_hash": TemporalReplayRequestSchema.SCHEMA_VERSION_HASH,
            "fork": fork,
            "replay_mode": "DRY_RUN",
            "runtime_registry_hash": "1" * 64,
            "max_steps": 0,
        }
        rr = TemporalReplayRequestSchema.from_dict(replay_req_dict)
        TemporalEngine.replay(context=ctx, request=rr)
        after = canonical_json(ctx)
        self.assertEqual(before, after)

