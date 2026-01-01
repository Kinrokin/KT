from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from cognition.cognitive_schemas import (
    MODE_LIVE_REQUESTED,
    PLAN_STATUS_OK,
    PLAN_STATUS_REFUSED,
    REFUSE_EXTERNAL_UNAVAILABLE,
    REFUSE_ILLEGAL_REFERENCE,
    REFUSE_POLICY,
    RESULT_STATUS_OK,
    RESULT_STATUS_REFUSED,
    STEP_STATUS_OK,
    CognitivePlanSchema,
    CognitiveRequestSchema,
    CognitiveResultSchema,
    CognitiveStepResultSchema,
)
from cognition.planners.step_planner import plan_steps
from schemas.base_schema import SchemaValidationError


@dataclass(frozen=True)
class ConstitutionalViolationError(RuntimeError):
    message: str

    def __str__(self) -> str:
        return self.message


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


def _has_illegal_reference(request_dict: Dict[str, Any]) -> bool:
    refs = request_dict.get("artifact_refs")
    if not isinstance(refs, list):
        return False
    for r in refs:
        if not isinstance(r, dict):
            continue
        aid = r.get("artifact_id")
        if isinstance(aid, str) and (aid.startswith("cognition.") or aid.startswith("cognition/")):
            return True
    return False


class CognitiveEngine:
    @staticmethod
    def _freeze_context_for_tests(context: Dict[str, Any]) -> Dict[str, Any]:
        return _freeze(context)

    @staticmethod
    def plan(*, context: Dict[str, Any], request: CognitiveRequestSchema) -> CognitivePlanSchema:
        _ = _freeze(context)

        req_dict = request.to_dict()
        CognitiveRequestSchema.validate(req_dict)
        request_hash = CognitiveRequestSchema.compute_request_hash(req_dict)

        plan_id = f"cognition.plan::{req_dict['request_id']}"

        refusal_code: str | None = None
        if req_dict["mode"] == MODE_LIVE_REQUESTED:
            refusal_code = REFUSE_EXTERNAL_UNAVAILABLE
        if _has_illegal_reference(req_dict):
            refusal_code = refusal_code or REFUSE_ILLEGAL_REFERENCE

        status = PLAN_STATUS_REFUSED if refusal_code else PLAN_STATUS_OK

        steps: List[Dict[str, Any]] = []
        if status == PLAN_STATUS_OK:
            steps = plan_steps(
                request_hash=request_hash,
                max_steps=int(req_dict["max_steps"]),
                artifact_refs=list(req_dict.get("artifact_refs") or []),
            )

        plan_payload: Dict[str, Any] = {
            "schema_id": CognitivePlanSchema.SCHEMA_ID,
            "schema_version_hash": CognitivePlanSchema.SCHEMA_VERSION_HASH,
            "plan_id": plan_id,
            "runtime_registry_hash": req_dict["runtime_registry_hash"],
            "request_hash": request_hash,
            "status": status,
            "mode": req_dict["mode"],
            "steps": steps,
            "plan_hash": "",
        }
        if refusal_code:
            plan_payload["refusal_code"] = refusal_code

        plan_payload["plan_hash"] = CognitivePlanSchema.compute_plan_hash(plan_payload)
        CognitivePlanSchema.validate(plan_payload)
        return CognitivePlanSchema.from_dict(plan_payload)

    @staticmethod
    def execute(*, context: Dict[str, Any], plan: CognitivePlanSchema) -> CognitiveResultSchema:
        _ = _freeze(context)

        plan_dict = plan.to_dict()
        CognitivePlanSchema.validate(plan_dict)

        if plan_dict["status"] != PLAN_STATUS_OK:
            payload = {
                "schema_id": CognitiveResultSchema.SCHEMA_ID,
                "schema_version_hash": CognitiveResultSchema.SCHEMA_VERSION_HASH,
                "status": RESULT_STATUS_REFUSED,
                "plan_hash": plan_dict["plan_hash"],
                "steps": [],
                "refusal_code": plan_dict.get("refusal_code") or REFUSE_POLICY,
                "result_hash": "",
            }
            payload["result_hash"] = CognitiveResultSchema.compute_result_hash(payload)
            CognitiveResultSchema.validate(payload)
            return CognitiveResultSchema.from_dict(payload)

        steps_value = plan_dict.get("steps")
        if not isinstance(steps_value, list):
            raise SchemaValidationError("plan.steps must be a list (fail-closed)")

        step_results: List[Dict[str, Any]] = []
        for step in steps_value:
            if not isinstance(step, dict):
                raise SchemaValidationError("plan.steps contains non-object step (fail-closed)")
            step_index = int(step["step_index"])
            step_type = str(step["step_type"])
            step_hash = str(step["step_hash"])

            # Deterministic per-step score derived from step_hash prefix.
            try:
                score = int(step_hash[0:2], 16) % 101
            except Exception:
                score = 0

            step_payload: Dict[str, Any] = {
                "schema_id": CognitiveStepResultSchema.SCHEMA_ID,
                "schema_version_hash": CognitiveStepResultSchema.SCHEMA_VERSION_HASH,
                "step_index": step_index,
                "step_type": step_type,
                "status": STEP_STATUS_OK,
                "score_0_100": score,
                "step_result_hash": "",
            }
            step_payload["step_result_hash"] = CognitiveStepResultSchema.compute_step_result_hash(step_payload)
            CognitiveStepResultSchema.validate(step_payload)
            step_results.append(step_payload)

        payload = {
            "schema_id": CognitiveResultSchema.SCHEMA_ID,
            "schema_version_hash": CognitiveResultSchema.SCHEMA_VERSION_HASH,
            "status": RESULT_STATUS_OK,
            "plan_hash": plan_dict["plan_hash"],
            "steps": step_results,
            "result_hash": "",
        }
        payload["result_hash"] = CognitiveResultSchema.compute_result_hash(payload)
        CognitiveResultSchema.validate(payload)
        return CognitiveResultSchema.from_dict(payload)
