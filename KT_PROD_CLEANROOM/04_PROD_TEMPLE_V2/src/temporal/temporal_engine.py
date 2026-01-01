from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from schemas.schema_hash import sha256_json
from temporal.temporal_schemas import (
    TemporalForkRequestSchema,
    TemporalForkSchema,
    TemporalReplayRequestSchema,
    TemporalReplayResultSchema,
)


RuntimeContext = Dict[str, Any]


@dataclass(frozen=True)
class TemporalEngineError(RuntimeError):
    message: str

    def __str__(self) -> str:
        return self.message


def _context_identity_hash(context: RuntimeContext) -> str:
    if not isinstance(context, dict):
        raise TemporalEngineError("context must be a dict (fail-closed)")
    schema_id = context.get("schema_id")
    schema_version_hash = context.get("schema_version_hash")
    constitution_version_hash = context.get("constitution_version_hash")
    if not isinstance(schema_id, str) or not isinstance(schema_version_hash, str) or not isinstance(constitution_version_hash, str):
        raise TemporalEngineError("context is missing schema/constitution identifiers (fail-closed)")
    return sha256_json(
        {
            "schema_id": schema_id,
            "schema_version_hash": schema_version_hash,
            "constitution_version_hash": constitution_version_hash,
        }
    )


def _compute_fork_hash(*, request_hash: str, context_identity_hash: str, runtime_registry_hash: str, anchor_hash: str, trace_id: str, epoch_id: str, parent_fork_hash: Any) -> str:
    return sha256_json(
        {
            "request_hash": request_hash,
            "context_identity_hash": context_identity_hash,
            "runtime_registry_hash": runtime_registry_hash,
            "anchor_hash": anchor_hash,
            "trace_id": trace_id,
            "epoch_id": epoch_id,
            "parent_fork_hash": parent_fork_hash,
        }
    )


class TemporalEngine:
    @staticmethod
    def create_fork(*, context: RuntimeContext, request: TemporalForkRequestSchema) -> TemporalForkSchema:
        ctx_hash = _context_identity_hash(context)
        req = request.to_dict()
        request_hash = sha256_json(req)

        fork_hash = _compute_fork_hash(
            request_hash=request_hash,
            context_identity_hash=ctx_hash,
            runtime_registry_hash=req["runtime_registry_hash"],
            anchor_hash=req["anchor_hash"],
            trace_id=req["trace_id"],
            epoch_id=req["epoch_id"],
            parent_fork_hash=req.get("parent_fork_hash"),
        )

        return TemporalForkSchema.from_dict(
            {
                "schema_id": TemporalForkSchema.SCHEMA_ID,
                "schema_version_hash": TemporalForkSchema.SCHEMA_VERSION_HASH,
                "fork_hash": fork_hash,
                "request_hash": request_hash,
                "context_identity_hash": ctx_hash,
                "runtime_registry_hash": req["runtime_registry_hash"],
                "anchor_hash": req["anchor_hash"],
                "trace_id": req["trace_id"],
                "epoch_id": req["epoch_id"],
                "parent_fork_hash": req.get("parent_fork_hash"),
            }
        )

    @staticmethod
    def replay(*, context: RuntimeContext, request: TemporalReplayRequestSchema) -> TemporalReplayResultSchema:
        ctx_hash = _context_identity_hash(context)
        req = request.to_dict()
        fork_dict = req["fork"]
        fork = TemporalForkSchema.from_dict(fork_dict)
        fork_payload = fork.to_dict()

        if fork_payload["runtime_registry_hash"] != req["runtime_registry_hash"]:
            return _rejected_result(fork_hash=fork_payload["fork_hash"], code="REGISTRY_HASH_MISMATCH")
        if fork_payload["context_identity_hash"] != ctx_hash:
            return _rejected_result(fork_hash=fork_payload["fork_hash"], code="CONTEXT_IDENTITY_MISMATCH")

        replay_hash = sha256_json(
            {
                "fork_hash": fork_payload["fork_hash"],
                "fork_request_hash": fork_payload["request_hash"],
                "replay_mode": req["replay_mode"],
                "max_steps": req["max_steps"],
                "runtime_registry_hash": req["runtime_registry_hash"],
                "context_identity_hash": ctx_hash,
            }
        )

        steps_executed = 0
        outcome_hash = TemporalReplayResultSchema.compute_outcome_hash(
            status=TemporalReplayResultSchema.STATUS_OK,
            fork_hash=fork_payload["fork_hash"],
            replay_hash=replay_hash,
            steps_executed=steps_executed,
        )

        return TemporalReplayResultSchema.from_dict(
            {
                "schema_id": TemporalReplayResultSchema.SCHEMA_ID,
                "schema_version_hash": TemporalReplayResultSchema.SCHEMA_VERSION_HASH,
                "status": TemporalReplayResultSchema.STATUS_OK,
                "fork_hash": fork_payload["fork_hash"],
                "replay_hash": replay_hash,
                "outcome_hash": outcome_hash,
                "steps_executed": steps_executed,
                "rejection_code": None,
            }
        )


def _rejected_result(*, fork_hash: str, code: str) -> TemporalReplayResultSchema:
    replay_hash = "0" * 64
    outcome_hash = TemporalReplayResultSchema.compute_outcome_hash(
        status=TemporalReplayResultSchema.STATUS_REJECTED,
        fork_hash=fork_hash,
        replay_hash=replay_hash,
        steps_executed=0,
    )
    return TemporalReplayResultSchema.from_dict(
        {
            "schema_id": TemporalReplayResultSchema.SCHEMA_ID,
            "schema_version_hash": TemporalReplayResultSchema.SCHEMA_VERSION_HASH,
            "status": TemporalReplayResultSchema.STATUS_REJECTED,
            "fork_hash": fork_hash,
            "replay_hash": replay_hash,
            "outcome_hash": outcome_hash,
            "steps_executed": 0,
            "rejection_code": code,
        }
    )

