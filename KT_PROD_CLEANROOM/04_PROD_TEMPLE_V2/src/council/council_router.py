from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from council.council_schemas import (
    MODE_DRY_RUN,
    MODE_LIVE_REQUESTED,
    PLAN_STATUS_OK,
    PLAN_STATUS_REFUSED,
    RESULT_STATUS_DRY_RUN,
    RESULT_STATUS_REFUSED,
    CouncilPlanSchema,
    CouncilProviderCallSchema,
    CouncilRequestSchema,
    CouncilResultSchema,
)


@dataclass(frozen=True)
class ConstitutionalViolationError(RuntimeError):
    message: str

    def __str__(self) -> str:
        return self.message


ALLOWED_PROVIDER_IDS = {"dry_run"}


class _FrozenDict(dict):
    def __setitem__(self, key: object, value: object) -> None:  # noqa: ANN401
        raise ConstitutionalViolationError("RuntimeContext mutation attempted (fail-closed)")

    def update(self, *args: object, **kwargs: object) -> None:  # noqa: ANN401
        raise ConstitutionalViolationError("RuntimeContext mutation attempted (fail-closed)")


class _FrozenList(list):
    def __setitem__(self, key: object, value: object) -> None:  # noqa: ANN401
        raise ConstitutionalViolationError("RuntimeContext mutation attempted (fail-closed)")

    def append(self, value: object) -> None:  # noqa: ANN401
        raise ConstitutionalViolationError("RuntimeContext mutation attempted (fail-closed)")

    def extend(self, values: object) -> None:  # noqa: ANN401
        raise ConstitutionalViolationError("RuntimeContext mutation attempted (fail-closed)")


def _freeze(obj: Any) -> Any:  # noqa: ANN401
    if isinstance(obj, dict):
        return _FrozenDict({k: _freeze(v) for k, v in obj.items()})
    if isinstance(obj, list):
        return _FrozenList([_freeze(v) for v in obj])
    return obj


class CouncilRouter:
    @staticmethod
    def _freeze_context_for_tests(context: Dict[str, Any]) -> Dict[str, Any]:
        return _freeze(context)

    @staticmethod
    def plan(*, context: Dict[str, Any], request: CouncilRequestSchema) -> CouncilPlanSchema:
        ctx = _freeze(context)
        _ = ctx.get("schema_id")
        _ = ctx.get("constitution_version_hash")

        req = request.to_dict()
        CouncilRequestSchema.validate(req)
        request_hash = CouncilRequestSchema.compute_request_hash(req)

        plan_id = f"council.plan::{req['request_id']}"
        refusal_code: str | None = None

        mode = req["mode"]
        if mode == MODE_LIVE_REQUESTED:
            refusal_code = "LIVE_MODE_NOT_SUPPORTED"

        provider_ids = sorted([str(x) for x in req["provider_ids"]])
        if any(p not in ALLOWED_PROVIDER_IDS for p in provider_ids):
            refusal_code = refusal_code or "PROVIDER_NOT_ALLOWLISTED"

        status = PLAN_STATUS_REFUSED if refusal_code else PLAN_STATUS_OK

        calls: List[Dict[str, Any]] = []
        if status == PLAN_STATUS_OK:
            for p in provider_ids:
                call = {
                    "schema_id": CouncilProviderCallSchema.SCHEMA_ID,
                    "schema_version_hash": CouncilProviderCallSchema.SCHEMA_VERSION_HASH,
                    "provider_id": p,
                    "max_tokens": int(req["per_call_token_cap"]),
                    "performed": False,
                    "success": False,
                    "duration_ms": 0,
                    "output_hash": "0" * 64,
                }
                CouncilProviderCallSchema.validate(call)
                calls.append(call)

        payload: Dict[str, Any] = {
            "schema_id": CouncilPlanSchema.SCHEMA_ID,
            "schema_version_hash": CouncilPlanSchema.SCHEMA_VERSION_HASH,
            "plan_id": plan_id,
            "runtime_registry_hash": req["runtime_registry_hash"],
            "request_hash": request_hash,
            "status": status,
            "mode": mode,
            "provider_calls": calls,
            "plan_hash": "",
        }
        if refusal_code:
            payload["refusal_code"] = refusal_code

        payload["plan_hash"] = CouncilPlanSchema.compute_plan_hash(payload)
        CouncilPlanSchema.validate(payload)
        return CouncilPlanSchema.from_dict(payload)

    @staticmethod
    def execute(*, context: Dict[str, Any], plan: CouncilPlanSchema) -> CouncilResultSchema:
        _ = _freeze(context)

        plan_dict = plan.to_dict()
        CouncilPlanSchema.validate(plan_dict)

        if plan_dict["status"] != PLAN_STATUS_OK:
            result = {
                "schema_id": CouncilResultSchema.SCHEMA_ID,
                "schema_version_hash": CouncilResultSchema.SCHEMA_VERSION_HASH,
                "status": RESULT_STATUS_REFUSED,
                "plan_hash": plan_dict["plan_hash"],
                "calls": [],
                "refusal_code": plan_dict.get("refusal_code") or "PLAN_REFUSED",
                "result_hash": "",
            }
            result["result_hash"] = CouncilResultSchema.compute_result_hash(result)
            CouncilResultSchema.validate(result)
            return CouncilResultSchema.from_dict(result)

        if plan_dict["mode"] != MODE_DRY_RUN:
            result = {
                "schema_id": CouncilResultSchema.SCHEMA_ID,
                "schema_version_hash": CouncilResultSchema.SCHEMA_VERSION_HASH,
                "status": RESULT_STATUS_REFUSED,
                "plan_hash": plan_dict["plan_hash"],
                "calls": [],
                "refusal_code": "LIVE_MODE_NOT_SUPPORTED",
                "result_hash": "",
            }
            result["result_hash"] = CouncilResultSchema.compute_result_hash(result)
            CouncilResultSchema.validate(result)
            return CouncilResultSchema.from_dict(result)

        result = {
            "schema_id": CouncilResultSchema.SCHEMA_ID,
            "schema_version_hash": CouncilResultSchema.SCHEMA_VERSION_HASH,
            "status": RESULT_STATUS_DRY_RUN,
            "plan_hash": plan_dict["plan_hash"],
            "calls": [],
            "output_hashes": [],
            "result_hash": "",
        }
        result["result_hash"] = CouncilResultSchema.compute_result_hash(result)
        CouncilResultSchema.validate(result)
        return CouncilResultSchema.from_dict(result)

