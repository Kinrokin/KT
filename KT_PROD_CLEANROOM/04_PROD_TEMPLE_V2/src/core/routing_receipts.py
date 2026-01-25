from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from memory.state_vault import StateVault
from schemas.adapter_invocation_schema import (
    ADAPTER_INVOCATION_SCHEMA_ID,
    ADAPTER_INVOCATION_SCHEMA_VERSION_HASH,
)
from schemas.routing_record_schema import (
    ROUTING_RECORD_SCHEMA_ID,
    ROUTING_RECORD_SCHEMA_VERSION_HASH,
)
from schemas.schema_registry import validate_object_with_binding
from schemas.state_vault_schema import utc_now_iso_z


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


SRR_SCHEMA_VERSION_HASH = ROUTING_RECORD_SCHEMA_VERSION_HASH
AIR_SCHEMA_VERSION_HASH = ADAPTER_INVOCATION_SCHEMA_VERSION_HASH


def _content_hash(payload: Dict[str, Any], *, drop_keys: List[str]) -> str:
    data = {k: v for k, v in payload.items() if k not in set(drop_keys)}
    return _sha256_text(_canonical_json(data))


def _receipt_dir(vault_path: Path, name: str) -> Path:
    return vault_path.parent / name


@dataclass(frozen=True)
class RoutingRecord:
    record: Dict[str, Any]
    record_hash: str
    record_path: Path


@dataclass(frozen=True)
class AdapterInvocation:
    record: Dict[str, Any]
    record_hash: str
    record_path: Path


def build_routing_record(
    *,
    runtime_registry_hash: str,
    spine_run_hash: str,
    task_context_hash: str,
    task_context_ref: str,
    request_hash: str,
    plan_hash: str,
    status: str,
    mode: str,
    vault_path: Path,
    candidates: Optional[List[Dict[str, Any]]] = None,
    chosen_adapter: Optional[Dict[str, Any]] = None,
    router_reason: str = "council.dry_run",
    router_confidence: float = 0.0,
    governor_verdict: Optional[Dict[str, Any]] = None,
    parent_routing_record: Optional[str] = None,
) -> RoutingRecord:
    created_at = utc_now_iso_z()
    candidate_list = candidates or []
    if candidate_list:
        candidate_list = sorted(
            candidate_list,
            key=lambda c: (
                str(c.get("adapter_id", "")),
                str(c.get("adapter_version", "")),
            ),
        )
    record = {
        "schema_id": ROUTING_RECORD_SCHEMA_ID,
        "schema_version_hash": SRR_SCHEMA_VERSION_HASH,
        "routing_record_id": "",
        "runtime_registry_hash": runtime_registry_hash,
        "spine_run_hash": spine_run_hash,
        "task_context_hash": task_context_hash,
        "task_context_ref": task_context_ref,
        "request_hash": request_hash,
        "plan_hash": plan_hash,
        "candidates": candidate_list,
        "chosen_adapter": chosen_adapter or {"adapter_id": "none", "adapter_version": "0"},
        "router_reason": router_reason,
        "router_confidence": float(router_confidence),
        "governor_verdict": governor_verdict
        or {
            "policy": "PolicyC",
            "verdict": "DRY_RUN" if mode == "DRY_RUN" else "DENY",
            "risk_score": 0.0,
            "verdict_hash": _sha256_text("policy_c_dry_run"),
        },
        "parent_routing_record": parent_routing_record,
        "status": "DRY_RUN" if mode == "DRY_RUN" and status == "OK" else status,
        "created_at": created_at,
    }
    record_hash = _content_hash(record, drop_keys=["created_at", "routing_record_id"])
    record["routing_record_id"] = record_hash
    out_dir = _receipt_dir(vault_path, "routing_records")
    record_path = out_dir / f"{record_hash}.json"
    return RoutingRecord(record=record, record_hash=record_hash, record_path=record_path)


def build_adapter_invocation(
    *,
    routing_record_hash: str,
    task_context_hash: str,
    input_hash: str,
    output_hash: Optional[str],
    status: str,
    vault_path: Path,
    adapter_id: str = "council.dry_run",
    adapter_version: str = "0",
    governor_verdict_hash: Optional[str] = None,
    evaluator_verdict: str = "SKIPPED",
    duration_ms: int = 0,
    token_usage: Optional[Mapping[str, int]] = None,
) -> AdapterInvocation:
    created_at = utc_now_iso_z()
    record = {
        "schema_id": ADAPTER_INVOCATION_SCHEMA_ID,
        "schema_version_hash": AIR_SCHEMA_VERSION_HASH,
        "invocation_id": "",
        "routing_record_hash": routing_record_hash,
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "task_context_hash": task_context_hash,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "governor_verdict_hash": governor_verdict_hash,
        "evaluator_verdict": evaluator_verdict,
        "duration_ms": int(duration_ms),
        "token_usage": dict(token_usage or {"prompt": 0, "completion": 0, "total": 0}),
        "status": status,
        "created_at": created_at,
    }
    record_hash = _content_hash(record, drop_keys=["created_at", "invocation_id"])
    record["invocation_id"] = record_hash
    out_dir = _receipt_dir(vault_path, "adapter_invocations")
    record_path = out_dir / f"{record_hash}.json"
    return AdapterInvocation(record=record, record_hash=record_hash, record_path=record_path)


def write_routing_record(*, vault: StateVault, routing: RoutingRecord, outputs_hash: str) -> str:
    validate_object_with_binding(routing.record)
    routing.record_path.parent.mkdir(parents=True, exist_ok=True)
    routing.record_path.write_text(_canonical_json(routing.record), encoding="utf-8")
    vault.append(
        event_type="ROUTING_RECORD",
        organ_id="CouncilRouter",
        inputs_hash=routing.record_hash,
        outputs_hash=outputs_hash,
    )
    return routing.record_hash


def write_adapter_invocation(*, vault: StateVault, invocation: AdapterInvocation, outputs_hash: str) -> str:
    validate_object_with_binding(invocation.record)
    invocation.record_path.parent.mkdir(parents=True, exist_ok=True)
    invocation.record_path.write_text(_canonical_json(invocation.record), encoding="utf-8")
    vault.append(
        event_type="ADAPTER_INVOCATION",
        organ_id="CouncilRouter",
        inputs_hash=invocation.record_hash,
        outputs_hash=outputs_hash,
    )
    return invocation.record_hash
