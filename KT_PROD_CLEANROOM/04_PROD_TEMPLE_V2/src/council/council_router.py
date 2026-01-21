
from __future__ import annotations

import os
from copy import deepcopy
from typing import Any, Dict, Mapping

from council.council_schemas import (
    CouncilPlanSchema,
    CouncilRequestSchema,
    CouncilResultSchema,
    MODE_DRY_RUN,
    MODE_LIVE_REQUESTED,
    PLAN_STATUS_OK,
    PLAN_STATUS_REFUSED,
    RESULT_STATUS_DRY_RUN,
    RESULT_STATUS_REFUSED,
)
from council.providers.provider_registry import ProviderRegistry
from council.providers.provider_schemas import ProviderCallReceipt


class CouncilError(RuntimeError):
    pass


class ConstitutionalViolationError(RuntimeError):
    pass

_ALLOWED_LIVE_HASHED_PROVIDERS = {"openai"}
_ALLOWED_LIVE_HASHED_REQUEST_TYPES = {"healthcheck", "analysis"}

def _require_live_hashed_env() -> None:
    if os.getenv("KT_PROVIDERS_ENABLED") != "1":
        raise CouncilError("KT_PROVIDERS_ENABLED=1 required (fail-closed).")
    if os.getenv("KT_EXECUTION_LANE") != "LIVE_HASHED":
        raise CouncilError("KT_EXECUTION_LANE=LIVE_HASHED required (fail-closed).")

def execute_council_request(req: Dict[str, Any]) -> Dict[str, Any]:
    mode = str(req.get("mode", "DRY_RUN"))
    request_type = str(req.get("request_type", "")).strip()

    if mode != "LIVE_HASHED":
        raise CouncilError("Only LIVE_HASHED mode is supported in this path (fail-closed).")

    _require_live_hashed_env()

    if request_type not in _ALLOWED_LIVE_HASHED_REQUEST_TYPES:
        raise CouncilError(f"request_type not allowlisted for LIVE_HASHED (fail-closed): {request_type!r}")

    provider_id = str(req.get("provider_id", "")).strip()
    if provider_id not in _ALLOWED_LIVE_HASHED_PROVIDERS:
        raise CouncilError(f"provider_id not allowlisted for LIVE_HASHED (fail-closed): {provider_id!r}")

    model = str(req.get("model", "")).strip()
    if not model:
        raise CouncilError("Missing model (fail-closed).")

    prompt = str(req.get("prompt", "")).strip()
    if not prompt:
        raise CouncilError("Missing prompt (fail-closed).")

    timeout_ms = int(req.get("timeout_ms", 20_000))
    temperature = float(req.get("temperature", 0.0))
    kt_node_id = str(req.get("kt_node_id", os.getenv("KT_NODE_ID", "")))

    registry = ProviderRegistry.build_default()

    receipt: ProviderCallReceipt = registry.invoke_live_hashed(
        provider_id=provider_id,
        model=model,
        prompt=prompt,
        timeout_ms=timeout_ms,
        temperature=temperature,
        kt_node_id=kt_node_id,
        trace_id=str(req.get("trace_id", "")).strip() or None,
    )

    out = {
        "status": "OK",
        "mode": "LIVE_HASHED",
        "provider_id": provider_id,
        "model": receipt.to_dict().get("model"),
        "receipt": receipt.to_dict(),
        "receipt_hash": receipt.to_dict().get("receipt_hash"),
    }
    return out


class _FrozenContext(dict):
    def __setitem__(self, *_a, **_k) -> None:  # type: ignore[override]
        raise ConstitutionalViolationError("RuntimeContext is read-only (fail-closed)")

    def __delitem__(self, *_a, **_k) -> None:  # type: ignore[override]
        raise ConstitutionalViolationError("RuntimeContext is read-only (fail-closed)")

    def update(self, *_a, **_k) -> None:  # type: ignore[override]
        raise ConstitutionalViolationError("RuntimeContext is read-only (fail-closed)")


def _freeze_context_for_tests(context: Mapping[str, Any]) -> Mapping[str, Any]:
    return _FrozenContext(deepcopy(dict(context)))


def _plan_for_request(request: CouncilRequestSchema) -> CouncilPlanSchema:
    req = request.to_dict()
    request_hash = CouncilRequestSchema.compute_request_hash(req)
    mode = req.get("mode")
    status = PLAN_STATUS_OK if mode == MODE_DRY_RUN else PLAN_STATUS_REFUSED
    refusal_code = None if status == PLAN_STATUS_OK else "LIVE_NOT_AVAILABLE"

    payload = {
        "schema_id": CouncilPlanSchema.SCHEMA_ID,
        "schema_version_hash": CouncilPlanSchema.SCHEMA_VERSION_HASH,
        "plan_id": "council.plan.v1",
        "runtime_registry_hash": req.get("runtime_registry_hash"),
        "request_hash": request_hash,
        "status": status,
        "mode": mode,
        "provider_calls": [],
        "refusal_code": refusal_code,
        "plan_hash": "",
    }
    payload["plan_hash"] = CouncilPlanSchema.compute_plan_hash(payload)
    return CouncilPlanSchema.from_dict(payload)


def _execute_plan(plan: CouncilPlanSchema) -> CouncilResultSchema:
    plan_obj = plan.to_dict()
    status = plan_obj.get("status")
    mode = plan_obj.get("mode")

    if status == PLAN_STATUS_REFUSED or mode == MODE_LIVE_REQUESTED:
        refusal_code = plan_obj.get("refusal_code") or "LIVE_NOT_AVAILABLE"
        payload = {
            "schema_id": CouncilResultSchema.SCHEMA_ID,
            "schema_version_hash": CouncilResultSchema.SCHEMA_VERSION_HASH,
            "status": RESULT_STATUS_REFUSED,
            "plan_hash": plan_obj.get("plan_hash"),
            "calls": [],
            "output_hashes": [],
            "refusal_code": refusal_code,
            "result_hash": "",
        }
    else:
        payload = {
            "schema_id": CouncilResultSchema.SCHEMA_ID,
            "schema_version_hash": CouncilResultSchema.SCHEMA_VERSION_HASH,
            "status": RESULT_STATUS_DRY_RUN,
            "plan_hash": plan_obj.get("plan_hash"),
            "calls": [],
            "output_hashes": [],
            "result_hash": "",
        }
    payload["result_hash"] = CouncilResultSchema.compute_result_hash(payload)
    return CouncilResultSchema.from_dict(payload)

class CouncilRouter:
    _freeze_context_for_tests = staticmethod(_freeze_context_for_tests)

    @staticmethod
    def plan(*, context: Mapping[str, Any], request: Any) -> CouncilPlanSchema:
        # Context is read-only by contract; caller can assert immutability in tests.
        req = request.to_dict() if isinstance(request, CouncilRequestSchema) else request
        return _plan_for_request(CouncilRequestSchema.from_dict(req))

    @staticmethod
    def execute(*, context: Mapping[str, Any], plan: Any) -> CouncilResultSchema:
        pl = plan.to_dict() if isinstance(plan, CouncilPlanSchema) else plan
        return _execute_plan(CouncilPlanSchema.from_dict(pl))


__all__ = [
    "ConstitutionalViolationError",
    "CouncilError",
    "CouncilRouter",
    "ProviderRegistry",
    "execute_council_request",
]
