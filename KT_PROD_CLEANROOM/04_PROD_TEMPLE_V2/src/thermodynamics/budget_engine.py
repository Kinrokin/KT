from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from schemas.base_schema import SchemaValidationError
from thermodynamics.budget_schemas import (
    REFUSE_BRANCHES_EXCEEDED,
    REFUSE_DURATION_EXCEEDED,
    REFUSE_ILLEGAL_REQUEST,
    REFUSE_MEMORY_EXCEEDED,
    REFUSE_NESTED_ALLOCATION,
    REFUSE_SCHEMA,
    REFUSE_STEPS_EXCEEDED,
    REFUSE_TOKENS_EXCEEDED,
    STATUS_OK,
    BudgetAllocationSchema,
    BudgetConsumptionSchema,
    BudgetRequestSchema,
    BudgetResultSchema,
    budget_ok_allocation,
    budget_refusal_allocation,
    budget_result_ok,
    budget_result_refused,
    default_budget_request,
)
from thermodynamics.meters.duration_fuse import remaining_millis
from thermodynamics.meters.memory_meter import remaining_bytes
from thermodynamics.meters.step_meter import remaining_branches, remaining_steps
from thermodynamics.meters.token_meter import remaining_tokens


RuntimeContext = Dict[str, Any]


@dataclass(frozen=True)
class BudgetEngineError(RuntimeError):
    message: str

    def __str__(self) -> str:
        return self.message


class BudgetEngine:
    @staticmethod
    def allocate(*, context: RuntimeContext, request: BudgetRequestSchema) -> BudgetAllocationSchema:
        # Budget allocation is deterministic: no semantic reads, no time, no IO.
        _ = context.get("schema_id") if isinstance(context, dict) else None
        _ = context.get("constitution_version_hash") if isinstance(context, dict) else None

        req = request.to_dict()
        try:
            BudgetRequestSchema.validate(req)
        except SchemaValidationError as exc:
            raise BudgetEngineError(f"Budget request schema invalid (fail-closed): {exc}")

        if req.get("parent_allocation_hash") != ("0" * 64):
            return budget_refusal_allocation(request=request, refusal_code=REFUSE_NESTED_ALLOCATION)

        return budget_ok_allocation(request=request)

    @staticmethod
    def allocate_default(*, context: RuntimeContext, runtime_registry_hash: str) -> BudgetAllocationSchema:
        req = default_budget_request(runtime_registry_hash=runtime_registry_hash)
        return BudgetEngine.allocate(context=context, request=req)

    @staticmethod
    def consume(*, context: RuntimeContext, allocation: BudgetAllocationSchema, usage: BudgetConsumptionSchema) -> BudgetResultSchema:
        # Deterministic check only. Caller must halt on REFUSED.
        _ = context.get("schema_id") if isinstance(context, dict) else None

        alloc = allocation.to_dict()
        u = usage.to_dict()

        try:
            BudgetAllocationSchema.validate(alloc)
            BudgetConsumptionSchema.validate(u)
        except SchemaValidationError:
            return budget_result_refused(allocation=allocation, refusal_code=REFUSE_SCHEMA)

        if alloc["status"] != STATUS_OK:
            return budget_result_refused(allocation=allocation, refusal_code=alloc.get("refusal_code") or REFUSE_ILLEGAL_REQUEST)

        if u["allocation_hash"] != alloc["allocation_hash"]:
            return budget_result_refused(allocation=allocation, refusal_code=REFUSE_ILLEGAL_REQUEST)

        try:
            token_remaining = remaining_tokens(ceiling_tokens=int(alloc["token_ceiling"]), used_tokens=int(u["tokens_used"]))
            step_remaining = remaining_steps(ceiling_steps=int(alloc["step_ceiling"]), used_steps=int(u["steps_used"]))
            branch_remaining = remaining_branches(
                ceiling_branches=int(alloc["branch_ceiling"]), used_branches=int(u["branches_used"])
            )
            byte_remaining = remaining_bytes(
                ceiling_bytes=int(alloc["memory_ceiling_bytes"]), used_bytes=int(u["memory_bytes_used"])
            )
            millis_remaining = remaining_millis(
                ceiling_millis=int(alloc["duration_ceiling_millis"]), used_millis=int(u["duration_millis_used"])
            )
        except Exception:
            return budget_result_refused(allocation=allocation, refusal_code=REFUSE_ILLEGAL_REQUEST)

        if token_remaining < 0:
            return budget_result_refused(allocation=allocation, refusal_code=REFUSE_TOKENS_EXCEEDED)
        if step_remaining < 0:
            return budget_result_refused(allocation=allocation, refusal_code=REFUSE_STEPS_EXCEEDED)
        if branch_remaining < 0:
            return budget_result_refused(allocation=allocation, refusal_code=REFUSE_BRANCHES_EXCEEDED)
        if byte_remaining < 0:
            return budget_result_refused(allocation=allocation, refusal_code=REFUSE_MEMORY_EXCEEDED)
        if millis_remaining < 0:
            return budget_result_refused(allocation=allocation, refusal_code=REFUSE_DURATION_EXCEEDED)

        return budget_result_ok(allocation=allocation, usage=usage)

